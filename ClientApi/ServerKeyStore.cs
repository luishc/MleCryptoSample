using Jose.keys;
using System.Security.Cryptography;

namespace ClientApi
{
    public interface IServerKeyStore
    {
        Task EnsureInitializedAsync(string discoveryUrl);
        ECDsa GetServerJwsPublic();
        CngKey GetServerEncPublic();
    }

    public sealed class ServerKeyStore : IServerKeyStore
    {
        private readonly object _sync = new();
        private bool _initialized;

        private ECDsa? _serverJwsPublic;
        private CngKey? _serverEncPublic;
        private readonly IHttpClientFactory _httpClientFactory;

        public ServerKeyStore(IHttpClientFactory httpClientFactory)
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
                _serverJwsPublic = ecdsa;
                _serverEncPublic = encPub;
                _initialized = true;
            }
        }

        public ECDsa GetServerJwsPublic() =>
            _serverJwsPublic ?? throw new InvalidOperationException("JWS pública do gateway não inicializada.");

        public CngKey GetServerEncPublic() =>
            _serverEncPublic ?? throw new InvalidOperationException("Chave ECDH pública do gateway não inicializada.");
    }
}