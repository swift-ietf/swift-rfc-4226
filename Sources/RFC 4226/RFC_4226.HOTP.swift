extension RFC_4226 {

    /// A HOTP generator: a shared secret, a code length and the hash HMAC runs on (section 5).
    ///
    /// RFC 4226 defines HOTP over HMAC-SHA-1, the default here; RFC 6238 also uses HMAC-SHA-256 and HMAC-SHA-512.
    public struct HOTP: Sendable {

        /// `K`: the shared secret.
        public let secret: [UInt8]

        /// `Digit`: the number of decimal digits in a code.
        public let digits: Int

        /// The HMAC the codes are computed with.
        public let hmac: RFC_2104.HMAC

        public init(
            secret: [UInt8],
            digits: Int = 6,
            hash: RFC_2104.Hash = .sha1
        ) throws(RFC_4226.Error) {
            guard !secret.isEmpty else { throw .emptySecret }
            guard (6...9).contains(digits) else { throw .digits(digits) }
            guard hash.outputLength >= 20 else { throw .hashOutputLength(hash.outputLength) }
            self.secret = secret
            self.digits = digits
            self.hmac = RFC_2104.HMAC(hash)
        }
    }
}

extension RFC_4226.HOTP {

    /// `DT` (section 5.3): four bytes of `hmac` at the offset its last byte's low nibble names, as a 31-bit number.
    ///
    /// `hmac` must be at least 20 bytes long.
    public static func truncate(_ hmac: [UInt8]) -> UInt32 {
        precondition(hmac.count >= 20, "dynamic truncation reads from a value of at least 20 bytes")
        let offset = Int(hmac[hmac.count - 1] & 0x0f)
        var value: UInt32 = 0
        for index in offset..<(offset + 4) {
            value = value << 8 | UInt32(hmac[index])
        }
        return value & 0x7fff_ffff
    }

    /// `HOTP(K, C)` as a number: the truncated HMAC of the counter, modulo 10 to the power of `digits`.
    public func value(counter: UInt64) -> UInt32 {
        var message = [UInt8](repeating: 0, count: 8)
        for index in 0..<8 {
            message[index] = UInt8(truncatingIfNeeded: counter >> (56 - 8 * UInt64(index)))
        }
        var modulus: UInt32 = 1
        for _ in 0..<digits { modulus *= 10 }
        return Self.truncate(hmac.code(for: message, key: secret)) % modulus
    }

    /// `HOTP(K, C)` as the code a person types: `digits` decimal digits, leading zeros kept.
    public func code(counter: UInt64) -> String {
        let decimal = String(value(counter: counter))
        return String(repeating: "0", count: digits - decimal.count) + decimal
    }

    /// The counter in `counter...counter + lookAhead` whose code is `code`, or `nil` when none is (section 7.2 and
    /// the look-ahead window of section 7.4).
    ///
    /// Every counter in the window is computed and compared without stopping at a match, so the time taken does
    /// not depend on where, or whether, the code matched. A server stores the returned counter plus one, so that
    /// no code is accepted twice.
    public func validate(_ code: String, counter: UInt64, lookAhead: UInt64 = 0) -> UInt64? {
        let candidate = Array(code.utf8)
        let last = counter.addingReportingOverflow(lookAhead).overflow ? UInt64.max : counter + lookAhead
        var matched: UInt64? = nil
        var current = counter
        while true {
            let expected = Array(self.code(counter: current).utf8)
            var difference: UInt8 = candidate.count == expected.count ? 0 : 1
            for index in 0..<min(candidate.count, expected.count) {
                difference |= candidate[index] ^ expected[index]
            }
            if difference == 0, matched == nil { matched = current }
            if current == last { break }
            current += 1
        }
        return matched
    }
}
