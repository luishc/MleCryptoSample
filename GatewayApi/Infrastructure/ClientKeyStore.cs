using GatewayApi.Infrastructure.Abstractions;
using System.Security.Cryptography;

namespace GatewayApi.Infrastructure
{
    public sealed class ClientKeyStore : IClientKeyStore
    {
        private readonly object _sync = new();
        private readonly Dictionary<string, (ECDsa Sig, CngKey Enc, string SigKid, string EncKid)> _byMerchant = new();

        public Task MergeMerchantKeysAsync(
            string merchantId,
            IReadOnlyDictionary<string, ECDsa> sigByKid,
            IReadOnlyDictionary<string, CngKey> encByKid)
        {
            if (string.IsNullOrWhiteSpace(merchantId))
                throw new ArgumentException("merchantId é obrigatório.", nameof(merchantId));

            // JWKS descontinuado: aceitamos exatamente 1 par ativo (sig/enc) e descartamos a chave do dicionário.
            var sig = sigByKid.Count == 1 ? sigByKid.Values.First() : throw new InvalidOperationException("Esperado exatamente 1 chave 'sig' para o merchant.");
            var enc = encByKid.Count == 1 ? encByKid.Values.First() : throw new InvalidOperationException("Esperado exatamente 1 chave 'enc' para o merchant.");
            var sigKid = sigByKid.Keys.First();
            var encKid = encByKid.Keys.First();

            lock (_sync)
            {
                _byMerchant[merchantId] = (sig, enc, sigKid, encKid);
            }

            return Task.CompletedTask;
        }

        public ECDsa GetClientJwsPublic(string merchantId, string kid)
        {
            lock (_sync)
            {
                if (_byMerchant.TryGetValue(merchantId, out var v))
                {
                    if (!string.Equals(v.SigKid, kid, StringComparison.Ordinal))
                        throw new InvalidOperationException($"kid inválido para merchant '{merchantId}'. Esperado '{v.SigKid}'.");
                    return v.Sig;
                }
            }
            throw new InvalidOperationException($"Chave JWS pública do cliente para merchant '{merchantId}' e kid '{kid}' não encontrada.");
        }

        public CngKey GetClientEncPublic(string merchantId, string kid)
        {
            lock (_sync)
            {
                if (_byMerchant.TryGetValue(merchantId, out var v))
                {
                    if (!string.Equals(v.EncKid, kid, StringComparison.Ordinal))
                        throw new InvalidOperationException($"kid inválido para merchant '{merchantId}'. Esperado '{v.EncKid}'.");
                    return v.Enc;
                }
            }
            throw new InvalidOperationException($"Chave ECDH pública do cliente para merchant '{merchantId}' e kid '{kid}' não encontrada.");
        }

        public string DeriveEncKidFromSigKid(string sigKid)
        {
            if (string.IsNullOrEmpty(sigKid)) throw new ArgumentException("sigKid inválido.", nameof(sigKid));
            if (sigKid.StartsWith("sig-", StringComparison.OrdinalIgnoreCase))
                return "enc-" + sigKid.Substring(4);
            return "enc-" + sigKid;
        }
    }
}
