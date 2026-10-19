import Testing
@testable import WardenrunCore

struct SHA256Tests {
    private func hex(_ text: String) -> String {
        SHA256.hexHash(Array(text.utf8))
    }

    @Test func emptyMessage() {
        #expect(hex("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    @Test func abc() {
        #expect(hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    }

    @Test func fourHundredFortyEightBitMessage() {
        #expect(hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
            == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
    }

    @Test(arguments: [1, 63, 64, 65, 4096])
    func millionAsInChunks(chunk: Int) {
        var hasher = SHA256()
        var remaining = 1_000_000
        let block = [UInt8](repeating: UInt8(ascii: "a"), count: chunk)
        while remaining > 0 {
            let take = min(chunk, remaining)
            hasher.update(Array(block[0..<take]))
            remaining -= take
        }
        #expect(Hex.encode(hasher.finalize()) == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
    }

    @Test(arguments: [
        (55, "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"),
        (56, "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"),
        (63, "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34"),
        (64, "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"),
        (65, "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0"),
    ])
    func paddingBoundaries(length: Int, expected: String) {
        let message = [UInt8](repeating: UInt8(ascii: "a"), count: length)
        #expect(SHA256.hexHash(message) == expected)
        var byteByByte = SHA256()
        for byte in message { byteByByte.update([byte]) }
        #expect(Hex.encode(byteByByte.finalize()) == expected)
    }

    @Test func updateFromRawBufferMatchesArrayUpdate() {
        let message = Array("The quick brown fox jumps over the lazy dog".utf8)
        var hasher = SHA256()
        message.withUnsafeBytes { hasher.update($0) }
        #expect(Hex.encode(hasher.finalize()) == SHA256.hexHash(message))
        #expect(SHA256.hexHash(message) == "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592")
    }

    @Test func finalizeDoesNotConsumeTheState() {
        var hasher = SHA256()
        hasher.update(Array("abc".utf8))
        let first = hasher.finalize()
        #expect(hasher.finalize() == first)
    }
}
