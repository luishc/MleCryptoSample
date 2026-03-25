using GatewayApi.Infrastructure.Abstractions;
using GatewayApi.Infrastructure.Helpers;
using GatewayApi.Models;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;

namespace GatewayApi.Infrastructure;

public sealed class LocalAppsettingsKeyMaterialProvider : IKeyMaterialProvider
{
    private readonly LocalKeysOptions _options;
    private bool _initialized;
    private readonly object _sync = new();

    private readonly Dictionary<string, ECDsa> _gatewaySigPrivByKid = new();
    private readonly Dictionary<string, CngKey> _gatewayEncPrivByKid = new();
    private string? _gatewaySigKid;
    private string? _gatewayEncKid;

    private readonly Dictionary<string, Dictionary<string, ECDsa>> _clientSigByMerchantAndKid = new();
    private readonly Dictionary<string, Dictionary<string, CngKey>> _clientEncByMerchantAndKid = new();

    public LocalAppsettingsKeyMaterialProvider(IOptions<LocalKeysOptions> options)
    {
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
    }

    public Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        if (_initialized) return Task.CompletedTask;
        lock (_sync)
        {
            if (_initialized) return Task.CompletedTask;

            _gatewaySigKid = _options.Gateway.SigKid;
            _gatewayEncKid = _options.Gateway.EncKid;
            _gatewaySigPrivByKid[_gatewaySigKid] = PemKeyLoader.LoadEcdsaPrivateFromPem(_options.Gateway.SigPrivateKeyPem);
            using var encEcdsa = PemKeyLoader.LoadEcdsaPrivateFromPem(_options.Gateway.EncPrivateKeyPem);
            _gatewayEncPrivByKid[_gatewayEncKid] = PemKeyLoader.ToKeyAgreementCngKey(encEcdsa, includePrivate: true);

            foreach (var (merchantId, mk) in _options.Merchants)
            {
                using var sigPub = PemKeyLoader.LoadEcdsaPublicFromPem(mk.SigPublicKeyPem);
                using var encPubEcdsa = PemKeyLoader.LoadEcdsaPublicFromPem(mk.EncPublicKeyPem);
                var sig = ECDsa.Create(sigPub.ExportParameters(false));
                var enc = PemKeyLoader.ToKeyAgreementCngKey(encPubEcdsa, includePrivate: false);
                _clientSigByMerchantAndKid[merchantId] = new Dictionary<string, ECDsa> { [mk.SigKid] = sig };
                _clientEncByMerchantAndKid[merchantId] = new Dictionary<string, CngKey> { [mk.EncKid] = enc };
            }

            _initialized = true;
        }

        return Task.CompletedTask;
    }

    public ECDsa GetGatewaySigPrivate() => _gatewaySigPrivByKid[_gatewaySigKid ?? throw new InvalidOperationException("Provider não inicializado.")];
    public CngKey GetGatewayEncPrivate(string kid)
    {
        if (_gatewayEncPrivByKid.TryGetValue(kid, out var key)) return key;
        throw new InvalidOperationException($"Chave privada ECDH do gateway para kid '{kid}' não encontrada.");
    }
    public string GetGatewaySigKid() => _gatewaySigKid ?? throw new InvalidOperationException("Provider não inicializado.");
    public string GetGatewayEncKid() => _gatewayEncKid ?? throw new InvalidOperationException("Provider não inicializado.");

    public IReadOnlyDictionary<string, ECDsa> GetClientSigPublicByKid(string merchantId)
    {
        if (_clientSigByMerchantAndKid.TryGetValue(merchantId, out var byKid)) return byKid;
        throw new InvalidOperationException($"Merchant '{merchantId}' não configurado em Gateway:LocalKeys:Merchants.");
    }

    public IReadOnlyDictionary<string, CngKey> GetClientEncPublicByKid(string merchantId)
    {
        if (_clientEncByMerchantAndKid.TryGetValue(merchantId, out var byKid)) return byKid;
        throw new InvalidOperationException($"Merchant '{merchantId}' não configurado em Gateway:LocalKeys:Merchants.");
    }
}

