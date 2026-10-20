import Foundation
import Testing
@testable import WardenrunCore

struct ParentDescriptionTests {
    @Test func theNearestParentThatIsNotAShellIsChosen() {
        #expect(ParentDescription.pick(["zsh", "node", "Terminal"]) == "node")
        #expect(ParentDescription.pick(["bash", "sh", "claude", "zsh"]) == "claude")
        #expect(ParentDescription.pick(["python3", "zsh"]) == "python3")
    }

    @Test func whenEveryParentIsAShellTheNearestIsChosen() {
        #expect(ParentDescription.pick(["zsh", "bash"]) == "zsh")
        #expect(ParentDescription.pick(["sudo", "login", "zsh"]) == "sudo")
    }

    @Test func noParentsGivesNil() {
        #expect(ParentDescription.pick([]) == nil)
    }

    @Test func aNameThatMerelyContainsAShellNameIsNotAShell() {
        #expect(ParentDescription.pick(["bashful-agent", "zsh"]) == "bashful-agent")
        #expect(ParentDescription.pick(["ZSH", "zsh"]) == "ZSH", "names are compared exactly")
    }
}
