using Jose.keys;
using System.Security.Cryptography;

namespace GatewayApi
{
    public sealed class ServerOwnKeyStore
    {
        // JWS (ES384)
        private readonly ECDsa _jwsPrivate;
        private readonly byte[] _jwsPublicSpki;
        // JWE (ECDH-ES)
        private readonly CngKey _encPrivate;
        private readonly byte[] _encX;
        private readonly byte[] _encY;
        public ServerOwnKeyStore()
        {
            // assinatura – P-384
            _jwsPrivate = ECDsa.Create(ECCurve.NamedCurves.nistP384);
            _jwsPublicSpki = _jwsPrivate.ExportSubjectPublicKeyInfo();
            // criptografia – ECDH P-256
            using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            var pub = ecdh.ExportParameters(false);
            var priv = ecdh.ExportParameters(true);
            _encX = pub.Q.X!;
            _encY = pub.Q.Y!;
            _encPrivate = EccKey.New(_encX, _encY, priv.D, CngKeyUsages.KeyAgreement);
        }
        public DiscoveryKeysDto GetDiscoveryKeys() => new()
        {
            JwsPublicKey = Convert.ToBase64String(_jwsPublicSpki),
            EncX = Convert.ToBase64String(_encX),
            EncY = Convert.ToBase64String(_encY)
        };
        public ECDsa GetJwsPrivate() => _jwsPrivate;
        public CngKey GetEncPrivate() => _encPrivate;
    }
}