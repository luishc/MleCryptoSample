using GatewayApi.Infrastructure.Abstractions;
using GatewayApi.Models;

namespace GatewayApi.Infrastructure
{
    public class DiscoveryClientsPublicKeys : IDiscoveryClientsPublicKeys
    {
        private readonly IConfiguration _configuration;
        private readonly IClientKeyStore _clientKeyStore;
        private readonly JwksMerchantKeysLoader _jwksLoader;
        private readonly KeyVaultMerchantKeysLoader _keyVaultLoader;

        public DiscoveryClientsPublicKeys(
            IConfiguration configuration,
            IClientKeyStore clientKeyStore,
            JwksMerchantKeysLoader jwksLoader,
            KeyVaultMerchantKeysLoader keyVaultLoader)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _clientKeyStore = clientKeyStore ?? throw new ArgumentNullException(nameof(clientKeyStore));
            _jwksLoader = jwksLoader ?? throw new ArgumentNullException(nameof(jwksLoader));
            _keyVaultLoader = keyVaultLoader ?? throw new ArgumentNullException(nameof(keyVaultLoader));
        }

        public async Task InitAsync()
        {
            var merchantsSection = _configuration.GetSection("Gateway:Merchants");
            var merchantChildren = merchantsSection.GetChildren().ToList();

            if (merchantChildren.Count == 0)
                throw new InvalidOperationException(
                    "Configure pelo menos um merchant em Gateway:Merchants (Source Discovery ou KeyVault). " +
                    "O modelo Gateway:ClientDiscovery não é mais suportado.");

            foreach (var child in merchantChildren)
            {
                var merchantId = child.Key;
                if (string.IsNullOrWhiteSpace(merchantId))
                    throw new InvalidOperationException("MerchantId inválido na seção Gateway:Merchants.");

                var entry = child.Get<MerchantKeysEntryOptions>()
                            ?? throw new InvalidOperationException($"Gateway:Merchants:{merchantId} não pôde ser lido.");

                if (string.IsNullOrWhiteSpace(entry.Source))
                    throw new InvalidOperationException($"Gateway:Merchants:{merchantId}: Source é obrigatório (Discovery ou KeyVault).");

                switch (entry.Source.Trim().ToLowerInvariant())
                {
                    case "discovery":
                        if (string.IsNullOrWhiteSpace(entry.DiscoveryUrl))
                            throw new InvalidOperationException($"Gateway:Merchants:{merchantId}: DiscoveryUrl é obrigatório quando Source=Discovery.");
                        await _jwksLoader.LoadAsync(merchantId, entry.DiscoveryUrl, _clientKeyStore);
                        break;

                    case "keyvault":
                        await _keyVaultLoader.LoadAsync(merchantId, _clientKeyStore);
                        break;

                    default:
                        throw new InvalidOperationException(
                            $"Gateway:Merchants:{merchantId}: Source '{entry.Source}' não suportado. Use Discovery ou KeyVault.");
                }
            }
        }
    }
}
