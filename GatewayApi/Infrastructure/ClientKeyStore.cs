using GatewayApi.Infrastructure.Abstractions;
using GatewayApi.Models;
using Jose.keys;
using System.Security.Cryptography;

namespace GatewayApi.Infrastructure
{
    public sealed class ClientKeyStore : IClientKeyStore
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
            var jwks = await client.GetFromJsonAsync<JwkSet>(discoveryUrl)
                       ?? throw new InvalidOperationException("JWKS do cliente inválido.");

            var sigKey = jwks.Keys.FirstOrDefault(k => k.Use == "sig")
                         ?? throw new InvalidOperationException("JWKS do cliente não contém chave de assinatura (use='sig').");

            var encKey = jwks.Keys.FirstOrDefault(k => k.Use == "enc")
                         ?? throw new InvalidOperationException("JWKS do cliente não contém chave de criptografia (use='enc').");

            var sigParams = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP384,
                Q = new ECPoint
                {
                    X = Base64Url.Decode(sigKey.X),
                    Y = Base64Url.Decode(sigKey.Y)
                }
            };

            var ecdsa = ECDsa.Create(sigParams);

            var encX = Base64Url.Decode(encKey.X);
            var encY = Base64Url.Decode(encKey.Y);
            var encPub = EccKey.New(encX, encY, d: null, usage: CngKeyUsages.KeyAgreement);

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