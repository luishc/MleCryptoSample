using Jose.keys;
using System.Security.Cryptography;

namespace GatewayApi
{
    public sealed class ClientKeyStore
    {
        private readonly object _sync = new();
        private bool _initialized;

        private ECDsa? _clientJwsPublic;
        private CngKey? _clientEncPublic;
        private readonly IHttpClientFactory _httpClientFactory;

        public ClientKeyStore(IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory;
        }

        public async Task EnsureInitializedAsync(string discoveryUrl)
        {
            if (_initialized) return;

            lock (_sync)
            {
                if (_initialized) return;
            }

            var client = _httpClientFactory.CreateClient();
            var resp = await client.GetFromJsonAsync<DiscoveryKeysDto>(discoveryUrl)
                       ?? throw new InvalidOperationException("Discovery do gateway inválido.");

            // JWS – chave pública ES384
            var jwsBytes = Convert.FromBase64String(resp.JwsPublicKey);
            var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(jwsBytes, out _);

            // JWE – chave pública ECDH-ES
            var x = Convert.FromBase64String(resp.EncX);
            var y = Convert.FromBase64String(resp.EncY);
            var encPub = EccKey.New(x, y, d: null, usage: CngKeyUsages.KeyAgreement);

            lock (_sync)
            {
                _clientJwsPublic = ecdsa;
                _clientEncPublic = encPub;
                _initialized = true;
            }
        }

        public ECDsa GetClientJwsPublic() =>
            _clientJwsPublic ?? throw new InvalidOperationException("JWS pública do gateway não inicializada.");

        public CngKey GetClientEncPublic() =>
            _clientEncPublic ?? throw new InvalidOperationException("Chave ECDH pública do gateway não inicializada.");
    }
}