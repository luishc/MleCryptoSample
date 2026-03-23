using Jose.keys;
using System.Security.Cryptography;

namespace ClientApi
{
    public interface IServerKeyStore
    {
        Task EnsureInitializedAsync(string discoveryUrl);
        string GetCurrentSigKid();
        string GetCurrentEncKid();
        ECDsa GetServerJwsPublic(string kid);
        CngKey GetServerEncPublic(string kid);
    }

    public sealed class ServerKeyStore : IServerKeyStore
    {
        private readonly object _sync = new();
        private bool _initialized;
        private readonly Dictionary<string, ECDsa> _jwsByKid = new();
        private readonly Dictionary<string, CngKey> _encByKid = new();
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
            var jwks = await client.GetFromJsonAsync<JwkSet>(discoveryUrl)
                       ?? throw new InvalidOperationException("JWKS do gateway inválido.");

            var sigKeys = jwks.Keys.Where(k => k.Use == "sig").ToList();
            var encKeys = jwks.Keys.Where(k => k.Use == "enc").ToList();
            if (sigKeys.Count == 0)
                throw new InvalidOperationException("JWKS do gateway não contém chave de assinatura (use='sig').");
            if (encKeys.Count == 0)
                throw new InvalidOperationException("JWKS do gateway não contém chave de criptografia (use='enc').");

            var jwsByKid = new Dictionary<string, ECDsa>();
            foreach (var k in sigKeys)
            {
                var p = new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP384,
                    Q = new ECPoint { X = Base64Url.Decode(k.X), Y = Base64Url.Decode(k.Y) }
                };
                jwsByKid[k.Kid] = ECDsa.Create(p);
            }

            var encByKid = new Dictionary<string, CngKey>();
            foreach (var k in encKeys)
            {
                var encX = Base64Url.Decode(k.X);
                var encY = Base64Url.Decode(k.Y);
                encByKid[k.Kid] = EccKey.New(encX, encY, d: null, usage: CngKeyUsages.KeyAgreement);
            }

            lock (_sync)
            {
                foreach (var kv in jwsByKid) _jwsByKid[kv.Key] = kv.Value;
                foreach (var kv in encByKid) _encByKid[kv.Key] = kv.Value;
                _initialized = true;
            }
        }

        public string GetCurrentSigKid()
        {
            lock (_sync)
            {
                var kid = _jwsByKid.Keys.OrderByDescending(x => x).FirstOrDefault();
                return kid ?? throw new InvalidOperationException("JWS pública do gateway não inicializada.");
            }
        }

        public string GetCurrentEncKid()
        {
            lock (_sync)
            {
                var kid = _encByKid.Keys.OrderByDescending(x => x).FirstOrDefault();
                return kid ?? throw new InvalidOperationException("Chave ECDH pública do gateway não inicializada.");
            }
        }

        public ECDsa GetServerJwsPublic(string kid)
        {
            lock (_sync)
            {
                if (_jwsByKid.TryGetValue(kid, out var key)) return key;
            }
            throw new InvalidOperationException($"Chave JWS pública do gateway para kid '{kid}' não encontrada.");
        }

        public CngKey GetServerEncPublic(string kid)
        {
            lock (_sync)
            {
                if (_encByKid.TryGetValue(kid, out var key)) return key;
            }
            throw new InvalidOperationException($"Chave ECDH pública do gateway para kid '{kid}' não encontrada.");
        }
    }
}
