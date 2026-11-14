extension RFC_4226 {

    /// Why a HOTP generator cannot be made.
    public enum Error: Swift.Error, Sendable, Equatable {

        /// The shared secret is empty.
        case emptySecret

        /// The number of digits is outside 6 through 9 (section 5.3 requires at least 6; a 31-bit value has 10
        /// digits, of which the leading one is not uniformly distributed).
        case digits(Int)

        /// The hash's output is shorter than the 20 bytes dynamic truncation reads from.
        case hashOutputLength(Int)
    }
}
