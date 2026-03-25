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

    private ECDsa? _clientSigPriv;
    private CngKey? _clientEncPriv;
    private string? _clientSigKid;
    private string? _clientEncKid;

    private ECDsa? _gatewaySigPub;
    private CngKey? _gatewayEncPub;
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
            _clientSigPriv = PemKeyLoader.LoadEcdsaFromPem(_options.Client.SigPrivateKeyPem);
            using var encPrivEcdsa = PemKeyLoader.LoadEcdsaFromPem(_options.Client.EncPrivateKeyPem);
            _clientEncPriv = PemKeyLoader.ToKeyAgreementCngKey(encPrivEcdsa, includePrivate: true);

            _gatewaySigKid = _options.Gateway.SigKid;
            _gatewayEncKid = _options.Gateway.EncKid;
            using var gwSig = PemKeyLoader.LoadEcdsaFromPem(_options.Gateway.SigPublicKeyPem);
            using var gwEnc = PemKeyLoader.LoadEcdsaFromPem(_options.Gateway.EncPublicKeyPem);
            _gatewaySigPub = ECDsa.Create(gwSig.ExportParameters(false));
            _gatewayEncPub = PemKeyLoader.ToKeyAgreementCngKey(gwEnc, includePrivate: false);

            _initialized = true;
        }

        return Task.CompletedTask;
    }

    public ECDsa GetClientSigPrivate() => _clientSigPriv ?? throw new InvalidOperationException("Provider não inicializado.");
    public CngKey GetClientEncPrivate() => _clientEncPriv ?? throw new InvalidOperationException("Provider não inicializado.");
    public string GetClientSigKid() => _clientSigKid ?? throw new InvalidOperationException("Provider não inicializado.");
    public string GetClientEncKid() => _clientEncKid ?? throw new InvalidOperationException("Provider não inicializado.");
    public ECDsa GetGatewaySigPublic() => _gatewaySigPub ?? throw new InvalidOperationException("Provider não inicializado.");
    public CngKey GetGatewayEncPublic() => _gatewayEncPub ?? throw new InvalidOperationException("Provider não inicializado.");
    public string GetGatewaySigKid() => _gatewaySigKid ?? throw new InvalidOperationException("Provider não inicializado.");
    public string GetGatewayEncKid() => _gatewayEncKid ?? throw new InvalidOperationException("Provider não inicializado.");
}

