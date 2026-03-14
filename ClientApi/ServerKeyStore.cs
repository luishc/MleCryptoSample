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
            var jwks = await client.GetFromJsonAsync<JwkSet>(discoveryUrl)
                       ?? throw new InvalidOperationException("JWKS do gateway inválido.");

            var sigKey = jwks.Keys.FirstOrDefault(k => k.Use == "sig")
                         ?? throw new InvalidOperationException("JWKS do gateway não contém chave de assinatura (use='sig').");

            var encKey = jwks.Keys.FirstOrDefault(k => k.Use == "enc")
                         ?? throw new InvalidOperationException("JWKS do gateway não contém chave de criptografia (use='enc').");

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