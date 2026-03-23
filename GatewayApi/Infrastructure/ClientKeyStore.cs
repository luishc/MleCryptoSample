using GatewayApi.Infrastructure.Abstractions;
using System.Security.Cryptography;

namespace GatewayApi.Infrastructure
{
    public sealed class ClientKeyStore : IClientKeyStore
    {
        private readonly object _sync = new();
        private readonly Dictionary<string, Dictionary<string, ECDsa>> _sigByMerchantAndKid = new();
        private readonly Dictionary<string, Dictionary<string, CngKey>> _encByMerchantAndKid = new();

        public Task MergeMerchantKeysAsync(
            string merchantId,
            IReadOnlyDictionary<string, ECDsa> sigByKid,
            IReadOnlyDictionary<string, CngKey> encByKid)
        {
            if (string.IsNullOrWhiteSpace(merchantId))
                throw new ArgumentException("merchantId é obrigatório.", nameof(merchantId));

            lock (_sync)
            {
                if (!_sigByMerchantAndKid.ContainsKey(merchantId))
                    _sigByMerchantAndKid[merchantId] = new Dictionary<string, ECDsa>();
                if (!_encByMerchantAndKid.ContainsKey(merchantId))
                    _encByMerchantAndKid[merchantId] = new Dictionary<string, CngKey>();

                foreach (var kv in sigByKid)
                    _sigByMerchantAndKid[merchantId][kv.Key] = kv.Value;
                foreach (var kv in encByKid)
                    _encByMerchantAndKid[merchantId][kv.Key] = kv.Value;
            }

            return Task.CompletedTask;
        }

        public ECDsa GetClientJwsPublic(string merchantId, string kid)
        {
            lock (_sync)
            {
                if (_sigByMerchantAndKid.TryGetValue(merchantId, out var byKid) && byKid.TryGetValue(kid, out var key))
                    return key;
            }
            throw new InvalidOperationException($"Chave JWS pública do cliente para merchant '{merchantId}' e kid '{kid}' não encontrada.");
        }

        public CngKey GetClientEncPublic(string merchantId, string kid)
        {
            lock (_sync)
            {
                if (_encByMerchantAndKid.TryGetValue(merchantId, out var byKid) && byKid.TryGetValue(kid, out var key))
                    return key;
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
