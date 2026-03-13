using Jose.keys;
using System.Security.Cryptography;

namespace GatewayApi
{
    public sealed class ClientKeyStore
    {
        private readonly object _sync = new();

        private readonly Dictionary<string, (ECDsa JwsPublic, CngKey EncPublic)> _byMerchant = new();
        private readonly IHttpClientFactory _httpClientFactory;

        public ClientKeyStore(IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory;
        }

        public async Task EnsureInitializedAsync(string merchantId, string discoveryUrl)
        {
            if (string.IsNullOrWhiteSpace(merchantId))
                throw new ArgumentException("merchantId é obrigatório.", nameof(merchantId));

            lock (_sync)
            {
                if (_byMerchant.ContainsKey(merchantId))
                    return;
            }

            var client = _httpClientFactory.CreateClient();
            var resp = await client.GetFromJsonAsync<DiscoveryKeysDto>(discoveryUrl)
                       ?? throw new InvalidOperationException("Discovery do cliente inválido.");

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
                if (!_byMerchant.ContainsKey(merchantId))
                    _byMerchant[merchantId] = (ecdsa, encPub);
            }
        }

        public ECDsa GetClientJwsPublic(string merchantId)
        {
            lock (_sync)
            {
                if (_byMerchant.TryGetValue(merchantId, out var entry))
                    return entry.JwsPublic;
            }

            throw new InvalidOperationException($"Chave JWS pública para merchant '{merchantId}' não inicializada.");
        }

        public CngKey GetClientEncPublic(string merchantId)
        {
            lock (_sync)
            {
                if (_byMerchant.TryGetValue(merchantId, out var entry))
                    return entry.EncPublic;
            }

            throw new InvalidOperationException($"Chave ECDH pública para merchant '{merchantId}' não inicializada.");
        }
    }
}