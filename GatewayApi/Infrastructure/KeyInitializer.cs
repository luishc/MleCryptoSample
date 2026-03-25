using GatewayApi.Infrastructure.Abstractions;
using System.Security.Cryptography;

namespace GatewayApi.Infrastructure;

public sealed class KeyInitializer : IKeyInitializer
{
    private readonly IKeyMaterialProvider _provider;
    private readonly IClientKeyStore _clientKeyStore;
    private readonly IConfiguration _configuration;

    public KeyInitializer(IKeyMaterialProvider provider, IClientKeyStore clientKeyStore, IConfiguration configuration)
    {
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
        _clientKeyStore = clientKeyStore ?? throw new ArgumentNullException(nameof(clientKeyStore));
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
    }

    public async Task InitAsync(CancellationToken cancellationToken = default)
    {
        await _provider.InitializeAsync(cancellationToken);

        // Load per-merchant client public keys into ClientKeyStore
        var merchantsSection = _configuration.GetSection("Gateway:Merchants");
        var merchantChildren = merchantsSection.GetChildren().ToList();
        if (merchantChildren.Count == 0)
            throw new InvalidOperationException("Configure pelo menos um merchant em Gateway:Merchants.");

        foreach (var child in merchantChildren)
        {
            var merchantId = child.Key;
            if (string.IsNullOrWhiteSpace(merchantId))
                throw new InvalidOperationException("MerchantId inválido na seção Gateway:Merchants.");

            var entry = child.Get<Models.MerchantKeysEntryOptions>()
                        ?? throw new InvalidOperationException($"Gateway:Merchants:{merchantId} não pôde ser lido.");

            if (!string.Equals(entry.Source?.Trim(), "KeyVault", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException($"Gateway:Merchants:{merchantId}: apenas Source=KeyVault é suportado.");

            await _clientKeyStore.MergeMerchantKeysAsync(
                merchantId,
                _provider.GetClientSigPublicByKid(merchantId),
                _provider.GetClientEncPublicByKid(merchantId));
        }
    }
}