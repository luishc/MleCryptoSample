using ClientApi.Infrastructure.Abstractions;
using ClientApi.Infrastructure.Helpers;
using ClientApi.Models;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;

namespace ClientApi.Infrastructure;

public sealed class LocalAppsettingsClientKeyMaterialProvider : IClientKeyMaterialProvider
{
    private readonly LocalClientKeysOptions _options;
    private bool _initialized;
    private readonly object _sync = new();

    private readonly Dictionary<string, ECDsa> _clientSigPrivByKid = new();
    private readonly Dictionary<string, CngKey> _clientEncPrivByKid = new();
    private string? _clientSigKid;
    private string? _clientEncKid;

    private readonly Dictionary<string, ECDsa> _gatewaySigPubByKid = new();
    private readonly Dictionary<string, CngKey> _gatewayEncPubByKid = new();
    private string? _gatewaySigKid;
    private string? _gatewayEncKid;

    public LocalAppsettingsClientKeyMaterialProvider(IOptions<LocalClientKeysOptions> options)
    {
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
    }

    public Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        if (_initialized) return Task.CompletedTask;
        lock (_sync)
        {
            if (_initialized) return Task.CompletedTask;

            _clientSigKid = _options.Client.SigKid;
            _clientEncKid = _options.Client.EncKid;
            _clientSigPrivByKid[_clientSigKid] = PemKeyLoader.LoadEcdsaFromPem(_options.Client.SigPrivateKeyPem);
            using var encPrivEcdsa = PemKeyLoader.LoadEcdsaFromPem(_options.Client.EncPrivateKeyPem);
            _clientEncPrivByKid[_clientEncKid] = PemKeyLoader.ToKeyAgreementCngKey(encPrivEcdsa, includePrivate: true);

            _gatewaySigKid = _options.Gateway.SigKid;
            _gatewayEncKid = _options.Gateway.EncKid;
            using var gwSig = PemKeyLoader.LoadEcdsaFromPem(_options.Gateway.SigPublicKeyPem);
            using var gwEnc = PemKeyLoader.LoadEcdsaFromPem(_options.Gateway.EncPublicKeyPem);
            _gatewaySigPubByKid[_gatewaySigKid] = ECDsa.Create(gwSig.ExportParameters(false));
            _gatewayEncPubByKid[_gatewayEncKid] = PemKeyLoader.ToKeyAgreementCngKey(gwEnc, includePrivate: false);

            _initialized = true;
        }

        return Task.CompletedTask;
    }

    public ECDsa GetClientSigPrivate() => _clientSigPrivByKid[_clientSigKid ?? throw new InvalidOperationException("Provider não inicializado.")];
    public CngKey GetClientEncPrivate(string kid)
    {
        if (_clientEncPrivByKid.TryGetValue(kid, out var key)) return key;
        throw new InvalidOperationException($"Chave privada ECDH do cliente para kid '{kid}' não encontrada.");
    }

    public string GetClientSigKid() => _clientSigKid ?? throw new InvalidOperationException("Provider não inicializado.");
    public string GetClientEncKid() => _clientEncKid ?? throw new InvalidOperationException("Provider não inicializado.");

    public ECDsa GetGatewaySigPublic(string kid)
    {
        if (_gatewaySigPubByKid.TryGetValue(kid, out var key)) return key;
        throw new InvalidOperationException($"Chave pública JWS do gateway para kid '{kid}' não encontrada.");
    }

    public CngKey GetGatewayEncPublic(string kid)
    {
        if (_gatewayEncPubByKid.TryGetValue(kid, out var key)) return key;
        throw new InvalidOperationException($"Chave pública ECDH do gateway para kid '{kid}' não encontrada.");
    }

    public string GetGatewaySigKid() => _gatewaySigKid ?? throw new InvalidOperationException("Provider não inicializado.");
    public string GetGatewayEncKid() => _gatewayEncKid ?? throw new InvalidOperationException("Provider não inicializado.");
}

