/// The RFC 5054 Appendix A groups AXIAM speaks (CONTRACT.md §23.4).
///
/// These moduli are embedded as constants and a modulus is **never** accepted from
/// the server: a server-supplied `N` is a server-supplied trapdoor. `SrpVectorsTests`
/// asserts each one's width, primality and safe-primality, because a transcription
/// slip here is a silent, total break that a client/server round-trip cannot catch —
/// both sides would share the same wrong constant.
public struct SrpGroup: Sendable, Equatable {

    /// The name this group carries on the wire, e.g. `rfc5054_4096`.
    public let wireName: String

    /// The modulus `N`, uppercase hex.
    public let modulusHex: String

    /// The generator `g`.
    public let generator: UInt64

    /// The modulus width in bytes — the width every hashed value is padded to
    /// (§23.3 rule 1).
    public let byteLength: Int

    /// The AXIAM default: it matches the RSA-4096 floor the project already sets for
    /// certificates.
    public static let defaultWireName = "rfc5054_4096"

    private enum Moduli {
    static let n2048 =
            "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050" +
            "A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50" +
            "E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8" +
            "55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B" +
            "CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748" +
            "544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6" +
            "AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6" +
            "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"

    static let n3072 =
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
            "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
            "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" +
            "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" +
            "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
            "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33" +
            "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
            "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864" +
            "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2" +
            "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"

    static let n4096 =
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
            "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
            "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" +
            "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" +
            "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
            "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33" +
            "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
            "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864" +
            "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2" +
            "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7" +
            "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8" +
            "DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2" +
            "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9" +
            "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF"
    }

    public static let rfc5054_2048 = SrpGroup(
        wireName: "rfc5054_2048", modulusHex: Moduli.n2048, generator: 2, byteLength: 256)
    public static let rfc5054_3072 = SrpGroup(
        wireName: "rfc5054_3072", modulusHex: Moduli.n3072, generator: 5, byteLength: 384)
    public static let rfc5054_4096 = SrpGroup(
        wireName: "rfc5054_4096", modulusHex: Moduli.n4096, generator: 5, byteLength: 512)

    /// Every group this SDK implements.
    public static let all: [SrpGroup] = [rfc5054_2048, rfc5054_3072, rfc5054_4096]

    /// Resolves a wire group name, refusing anything this SDK does not recognise
    /// rather than guessing (§23.4).
    ///
    /// - Returns: The group, or `nil` for a name this SDK does not implement. The
    ///   caller reports that as a ``NetworkError``, never an ``AuthError`` — a client
    ///   capability gap reported as a credential failure would send a user off to
    ///   reset a password that works.
    public static func fromWire(_ wireName: String) -> SrpGroup? {
        all.first { $0.wireName == wireName }
    }
}
