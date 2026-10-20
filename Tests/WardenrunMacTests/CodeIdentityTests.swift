#if canImport(Darwin)
import Foundation
import Testing
import WardenrunCore
@testable import WardenrunMac

private func tempDirectory() -> String {
    let path = (NSTemporaryDirectory() as NSString).appendingPathComponent("wardenrun-mac-" + UUID().uuidString)
    try? FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true)
    return path
}

/// A copy of `/bin/echo` signed ad hoc (the signature of every unsigned-then-linker-signed build).
private func adHocCopy(in directory: String) throws -> String {
    let path = directory + "/echo"
    try FileManager.default.copyItem(atPath: "/bin/echo", toPath: path)
    let codesign = Process()
    codesign.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
    codesign.arguments = ["--force", "--sign", "-", path]
    codesign.standardError = FileHandle.nullDevice
    try codesign.run()
    codesign.waitUntilExit()
    try #require(codesign.terminationStatus == 0)
    return path
}

struct CodeIdentityTests {
    private let checker = SecuritySignatureChecker()

    @Test func requirementTextHasTheDeveloperIDShapeAndEmbedsTheTeamOnlyAfterValidation() throws {
        let text = try #require(SecuritySignatureChecker.requirementText(teamID: "LTZ2PFU5D6"))
        #expect(text == "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists"
            + " and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
            + " and certificate leaf[subject.OU] = \"LTZ2PFU5D6\"")
        for bad in ["", "ltz2pfu5d6", "LTZ2PFU5D", "LTZ2PFU5D6X", "LTZ\"2PFU5D", "A\" or anchor apple", "LTZ2PFU5D\n", "ŁTZ2PFU5D6"] {
            #expect(SecuritySignatureChecker.requirementText(teamID: bad) == nil, "\(bad.debugDescription)")
        }
    }

    @Test func aTeamIDWithAQuoteIsRefusedBeforeAnyRequirementIsBuilt() {
        #expect(throws: BwError.signatureMismatch) { try checker.check(path: "/bin/ls", teamID: "A\" or anchor apple") }
    }

    @Test func anUnsignedFileIsRefused() throws {
        let directory = tempDirectory()
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let path = directory + "/script"
        try Data("#!/bin/sh\necho hi\n".utf8).write(to: URL(fileURLWithPath: path))
        chmod(path, 0o755)
        #expect(throws: BwError.signatureMismatch) { try checker.check(path: path, teamID: "LTZ2PFU5D6") }
    }

    @Test func anAdHocSignedCopyOfAFileIsRefusedForAnyTeam() throws {
        let directory = tempDirectory()
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let path = try adHocCopy(in: directory)
        for team in ["LTZ2PFU5D6", "ABCDEFGHIJ"] {
            #expect(throws: BwError.signatureMismatch) { try checker.check(path: path, teamID: team) }
        }
    }

    @Test func appleSignedPlatformBinaryIsRefusedForTheBitwardenTeam() {
        #expect(throws: BwError.signatureMismatch) { try checker.check(path: "/bin/ls", teamID: "LTZ2PFU5D6") }
    }

    @Test func aMissingFileIsRefused() {
        #expect(throws: BwError.signatureMismatch) { try checker.check(path: "/nonexistent/bw", teamID: "LTZ2PFU5D6") }
    }

    @Test func aSignedFileChangedAfterSigningIsRefused() throws {
        let directory = tempDirectory()
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let path = try adHocCopy(in: directory)
        // Ad-hoc is refused anyway; the point is that a tampered file never gets through either.
        let handle = try FileHandle(forUpdating: URL(fileURLWithPath: path))
        try handle.seekToEnd()
        try handle.write(contentsOf: Data([0x00]))
        try handle.close()
        #expect(throws: BwError.signatureMismatch) { try checker.check(path: path, teamID: "LTZ2PFU5D6") }
    }

    @Test func identityOfAnAdHocFileReportsAdHocAndNoTeam() throws {
        let directory = tempDirectory()
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let copy = try adHocCopy(in: directory)
        let identity = try #require(CodeIdentityReader.ofFile(copy))
        #expect(identity.isAdHoc)
        #expect(identity.teamID == nil)
        #expect(identity.certificateSHA1 == nil)
        #expect(identity.identifier != nil)
    }

    @Test func identityOfAMissingOrUnsignedFileIsNil() throws {
        #expect(CodeIdentityReader.ofFile("/nonexistent/bw") == nil)
        let directory = tempDirectory()
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let path = directory + "/plain"
        try Data("text".utf8).write(to: URL(fileURLWithPath: path))
        #expect(CodeIdentityReader.ofFile(path) == nil)
    }

    @Test func theCurrentProcessHasAnIdentity() {
        #expect(CodeIdentityReader.ofCurrentProcess() != nil)
    }

    @Test func applePlatformBinaryIsNotAdHocAndHasNoDeveloperIDTeam() throws {
        let identity = try #require(CodeIdentityReader.ofFile("/bin/ls"))
        #expect(!identity.isAdHoc)
        #expect(identity.certificateSHA1 == nil || identity.certificateSHA1?.count == 40)
    }

    // The maintainer runs these two with the official `bw` from the GitHub release:
    //   WARDENRUN_TEST_BW=/path/to/bw swift test --filter CodeIdentityTests
    private static let realBw = ProcessInfo.processInfo.environment["WARDENRUN_TEST_BW"]

    @Test(.enabled(if: realBw != nil)) func ifTheRealBwIsPresentItIsAcceptedForTheBitwardenTeamOnly() throws {
        let path = try #require(Self.realBw)
        try checker.check(path: path, teamID: "LTZ2PFU5D6")
        #expect(throws: BwError.signatureMismatch) { try checker.check(path: path, teamID: "ABCDEFGHIJ") }
    }

    @Test(.enabled(if: realBw != nil)) func ifTheRealBwIsPresentItsIdentityIsReadAsHardenedAndDeveloperID() throws {
        let path = try #require(Self.realBw)
        let identity = try #require(CodeIdentityReader.ofFile(path))
        #expect(identity.teamID == "LTZ2PFU5D6")
        #expect(identity.isHardened)
        #expect(!identity.isAdHoc)
        #expect(identity.certificateSHA1?.count == 40)
        #expect(identity.certificateSHA1?.allSatisfy { "0123456789abcdef".contains($0) } == true)
        #expect(identity.designatedRequirement?.contains("LTZ2PFU5D6") == true)
    }
}
#endif
