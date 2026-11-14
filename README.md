# swift-rfc-4226

Use this package for counter-based one-time passwords (HOTP), the six-to-nine digit codes of hardware tokens, either to generate them or to check one a person typed. Start from `RFC_4226.HOTP`. For time-based codes, use swift-rfc-6238, which is built on this.

## Laws

- Codes and the intermediate values match RFC 4226 Appendix D, and dynamic truncation matches the example of section 5.4.
- HMAC is RFC 2104 over SHA-1 by default. Any `RFC_2104.Hash` with an output of at least 20 bytes may be used instead.
- A code is always exactly `digits` characters long, with leading zeros kept. `digits` is 6 through 9, and the secret is never empty.
- `validate(_:counter:lookAhead:)` returns the counter whose code matched, so the caller can store the next counter and refuse a code used before. It computes and compares every counter in the window, whether or not one matched, and never wraps past the largest counter.
