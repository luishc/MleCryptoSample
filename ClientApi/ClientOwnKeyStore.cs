using System.Security.Cryptography;
using Jose;
using Jose.keys;

namespace ClientApi
{
    public interface IClientOwnKeyStore
    {
        DiscoveryKeysDto GetDiscoveryKeys();
        ECDsa GetJwsPrivate();
        CngKey GetEncPrivate();
        IReadOnlyCollection<JwkKey> GetJwkKeys();
    }

    public sealed class ClientOwnKeyStore : IClientOwnKeyStore
    {
        private readonly ECDsa _jwsPrivate;
        private readonly byte[] _jwsPublicSpki;
        private readonly CngKey _encPrivate;
        private readonly byte[] _encX;
        private readonly byte[] _encY;
        private readonly IReadOnlyCollection<JwkKey> _jwkKeys;

        public ClientOwnKeyStore()
        {
            _jwsPrivate = ECDsa.Create(ECCurve.NamedCurves.nistP384);
            _jwsPublicSpki = _jwsPrivate.ExportSubjectPublicKeyInfo();

            using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            var pub = ecdh.ExportParameters(false);
            var priv = ecdh.ExportParameters(true);
            _encX = pub.Q.X!;
            _encY = pub.Q.Y!;
            _encPrivate = EccKey.New(_encX, _encY, priv.D, CngKeyUsages.KeyAgreement);

            _jwkKeys = BuildInitialJwks();
        }

        public DiscoveryKeysDto GetDiscoveryKeys() => new()
        {
            JwsPublicKey = Convert.ToBase64String(_jwsPublicSpki),
            EncX = Convert.ToBase64String(_encX),
            EncY = Convert.ToBase64String(_encY)
        };

        public ECDsa GetJwsPrivate() => _jwsPrivate;
        public CngKey GetEncPrivate() => _encPrivate;

        public IReadOnlyCollection<JwkKey> GetJwkKeys() => _jwkKeys;

        private IReadOnlyCollection<JwkKey> BuildInitialJwks()
        {
            var keys = new List<JwkKey>();

            var sigParams = _jwsPrivate.ExportParameters(false);
            var sigKid = $"sig-{DateTime.UtcNow:yyyy-MM}";

            keys.Add(new JwkKey
            {
                Kty = "EC",
                Use = "sig",
                Kid = sigKid,
                Crv = "P-384",
                Alg = "ES384",
                X = Base64Url.Encode(sigParams.Q.X!),
                Y = Base64Url.Encode(sigParams.Q.Y!)
            });

            var encKid = $"enc-{DateTime.UtcNow:yyyy-MM}";

            keys.Add(new JwkKey
            {
                Kty = "EC",
                Use = "enc",
                Kid = encKid,
                Crv = "P-256",
                Alg = "ECDH-ES",
                X = Base64Url.Encode(_encX),
                Y = Base64Url.Encode(_encY)
            });

            return keys;
        }
    }
}
