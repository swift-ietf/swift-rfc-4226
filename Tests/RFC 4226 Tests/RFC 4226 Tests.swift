import Testing

import RFC_4226

@Suite
struct `RFC 4226 Tests` {

    static let secret = Array("12345678901234567890".utf8)

    @Test
    func `Appendix D intermediate HMAC values`() {
        let hmac = RFC_2104.HMAC(.sha1)
        let expected = [
            "cc93cf18508d94934c64b65d8ba7667fb7cde4b0",
            "75a48a19d4cbe100644e8ac1397eea747a2d33ab",
            "0bacb7fa082fef30782211938bc1c5e70416ff44",
            "66c28227d03a2d5529262ff016a1e6ef76557ece",
            "a904c900a64b35909874b33e61c5938a8e15ed1c",
            "a37e783d7b7233c083d4f62926c7a25f238d0316",
            "bc9cd28561042c83f219324d3c607256c03272ae",
            "a4fb960c0bc06e1eabb804e5b397cdc4b45596fa",
            "1b3c89f65e6c9e883012052823443f048b4332db",
            "1637409809a679dc698207310c8c7fc07290d9e5",
        ]
        for (count, value) in expected.enumerated() {
            let counter: [UInt8] = [0, 0, 0, 0, 0, 0, 0, UInt8(count)]
            #expect(hmac.code(for: counter, key: Self.secret) == hex(value))
        }
    }

    @Test
    func `Appendix D truncated values`() {
        let hmacs = [
            ("cc93cf18508d94934c64b65d8ba7667fb7cde4b0", 1_284_755_224),
            ("75a48a19d4cbe100644e8ac1397eea747a2d33ab", 1_094_287_082),
            ("0bacb7fa082fef30782211938bc1c5e70416ff44", 137_359_152),
            ("66c28227d03a2d5529262ff016a1e6ef76557ece", 1_726_969_429),
            ("a904c900a64b35909874b33e61c5938a8e15ed1c", 1_640_338_314),
            ("a37e783d7b7233c083d4f62926c7a25f238d0316", 868_254_676),
            ("bc9cd28561042c83f219324d3c607256c03272ae", 1_918_287_922),
            ("a4fb960c0bc06e1eabb804e5b397cdc4b45596fa", 82_162_583),
            ("1b3c89f65e6c9e883012052823443f048b4332db", 673_399_871),
            ("1637409809a679dc698207310c8c7fc07290d9e5", 645_520_489),
        ]
        for (value, truncated) in hmacs {
            #expect(RFC_4226.HOTP.truncate(hex(value)) == UInt32(truncated))
        }
    }

    @Test
    func `Appendix D HOTP values`() throws {
        let hotp = try RFC_4226.HOTP(secret: Self.secret)
        let expected = [
            "755224", "287082", "359152", "969429", "338314",
            "254676", "287922", "162583", "399871", "520489",
        ]
        for (count, code) in expected.enumerated() {
            #expect(hotp.code(counter: UInt64(count)) == code)
        }
    }

    @Test
    func `section 5.4 example truncates at offset 10`() {
        let hmac = hex("1f8698690e02ca16618550ef7f19da8e945b555a")
        #expect(RFC_4226.HOTP.truncate(hmac) == 0x50ef_7f19)
        #expect(RFC_4226.HOTP.truncate(hmac) % 1_000_000 == 872_921)
    }

    @Test
    func `validate finds the counter inside the look-ahead window`() throws {
        let hotp = try RFC_4226.HOTP(secret: Self.secret)
        #expect(hotp.validate("755224", counter: 0) == 0)
        #expect(hotp.validate("969429", counter: 0, lookAhead: 5) == 3)
        #expect(hotp.validate("969429", counter: 0, lookAhead: 2) == nil)
        #expect(hotp.validate("755224", counter: 1, lookAhead: 5) == nil)
        #expect(hotp.validate("75522", counter: 0) == nil)
        #expect(hotp.validate("7552240", counter: 0) == nil)
    }

    @Test
    func `validate does not trap at the end of the counter range`() throws {
        let hotp = try RFC_4226.HOTP(secret: Self.secret)
        let code = hotp.code(counter: .max)
        #expect(hotp.validate(code, counter: .max - 1, lookAhead: 10) == .max)
    }

    @Test
    func `leading zeros are kept`() throws {
        let hotp = try RFC_4226.HOTP(secret: Self.secret, digits: 9)
        // Count 7 truncates to 82162583, eight digits.
        #expect(hotp.code(counter: 7) == "082162583")
    }

    @Test
    func `a generator refuses an empty secret, a code length outside 6 through 9, and a short hash`() {
        #expect(throws: RFC_4226.Error.emptySecret) { try RFC_4226.HOTP(secret: []) }
        #expect(throws: RFC_4226.Error.digits(5)) { try RFC_4226.HOTP(secret: Self.secret, digits: 5) }
        #expect(throws: RFC_4226.Error.digits(10)) { try RFC_4226.HOTP(secret: Self.secret, digits: 10) }
        let short = RFC_2104.Hash(blockLength: 64, outputLength: 16) { _ in [UInt8](repeating: 0, count: 16) }
        #expect(throws: RFC_4226.Error.hashOutputLength(16)) { try RFC_4226.HOTP(secret: Self.secret, hash: short) }
    }
}
