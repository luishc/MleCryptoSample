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

    private ECDsa? _gatewaySigPriv;
    private CngKey? _gatewayEncPriv;
    private string? _gatewaySigKid;
    private string? _gatewayEncKid;

    private readonly Dictionary<string, (ECDsa Sig, CngKey Enc, string SigKid, string EncKid)> _clientByMerchant = new();

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
            _gatewaySigPriv = PemKeyLoader.LoadEcdsaPrivateFromPem(_options.Gateway.SigPrivateKeyPem);
            using var encEcdsa = PemKeyLoader.LoadEcdsaPrivateFromPem(_options.Gateway.EncPrivateKeyPem);
            _gatewayEncPriv = PemKeyLoader.ToKeyAgreementCngKey(encEcdsa, includePrivate: true);

            foreach (var (merchantId, mk) in _options.Merchants)
            {
                using var sigPub = PemKeyLoader.LoadEcdsaPublicFromPem(mk.SigPublicKeyPem);
                using var encPubEcdsa = PemKeyLoader.LoadEcdsaPublicFromPem(mk.EncPublicKeyPem);
                var sig = ECDsa.Create(sigPub.ExportParameters(false));
                var enc = PemKeyLoader.ToKeyAgreementCngKey(encPubEcdsa, includePrivate: false);
                _clientByMerchant[merchantId] = (sig, enc, mk.SigKid, mk.EncKid);
            }

            _initialized = true;
        }

        return Task.CompletedTask;
    }

    public ECDsa GetGatewaySigPrivate() => _gatewaySigPriv ?? throw new InvalidOperationException("Provider não inicializado.");
    public CngKey GetGatewayEncPrivate() => _gatewayEncPriv ?? throw new InvalidOperationException("Provider não inicializado.");
    public string GetGatewaySigKid() => _gatewaySigKid ?? throw new InvalidOperationException("Provider não inicializado.");
    public string GetGatewayEncKid() => _gatewayEncKid ?? throw new InvalidOperationException("Provider não inicializado.");

    public ECDsa GetClientSigPublic(string merchantId) => GetMerchant(merchantId).Sig;
    public CngKey GetClientEncPublic(string merchantId) => GetMerchant(merchantId).Enc;
    public string GetClientSigKid(string merchantId) => GetMerchant(merchantId).SigKid;
    public string GetClientEncKid(string merchantId) => GetMerchant(merchantId).EncKid;

    private (ECDsa Sig, CngKey Enc, string SigKid, string EncKid) GetMerchant(string merchantId)
    {
        if (!_initialized) throw new InvalidOperationException("Provider não inicializado.");
        if (string.IsNullOrWhiteSpace(merchantId))
            throw new ArgumentException("merchantId é obrigatório.", nameof(merchantId));
        if (_clientByMerchant.TryGetValue(merchantId, out var v)) return v;
        throw new InvalidOperationException($"Merchant '{merchantId}' não configurado em Gateway:LocalKeys:Merchants.");
    }
}

