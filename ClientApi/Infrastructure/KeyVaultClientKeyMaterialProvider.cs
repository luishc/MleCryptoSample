using Azure.Core;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using ClientApi.Infrastructure.Abstractions;
using ClientApi.Models;
using Jose.keys;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ClientApi.Infrastructure;

public sealed class KeyVaultClientKeyMaterialProvider : IClientKeyMaterialProvider
{
    private readonly TokenCredential _credential;
    private readonly ClientKeyVaultOptions _options;
    private readonly IConfiguration _configuration;

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

    public KeyVaultClientKeyMaterialProvider(TokenCredential credential, IOptions<ClientKeyVaultOptions> options, IConfiguration configuration)
    {
        _credential = credential ?? throw new ArgumentNullException(nameof(credential));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        if (_initialized) return;
        lock (_sync)
        {
            if (_initialized) return;
        }

        var merchantId = _configuration["Client:MerchantId"]?.Trim();
        if (string.IsNullOrWhiteSpace(merchantId))
            throw new InvalidOperationException("Client:MerchantId é obrigatório para KV-only.");

        if (string.IsNullOrWhiteSpace(_options.Uri))
            throw new InvalidOperationException("Client:KeyVault:Uri é obrigatório.");
        var suffix = _options.CertificateVersionSuffix?.Trim();
        if (string.IsNullOrWhiteSpace(suffix))
            throw new InvalidOperationException("Client:KeyVault:CertificateVersionSuffix é obrigatório.");

        var vaultUri = new Uri(_options.Uri);
        var certClient = new CertificateClient(vaultUri, _credential);
        var secretClient = new SecretClient(vaultUri, _credential);

        // Client own private keys: sig-{MerchantId}-{suffix} / enc-{MerchantId}-{suffix}
        _clientSigKid = $"sig-{merchantId}-{suffix}";
        _clientEncKid = $"enc-{merchantId}-{suffix}";
        _clientSigPriv = await LoadEcdsaPrivateFromCertificateSecretAsync(secretClient, _clientSigKid, cancellationToken);
        using var encEcdsa = await LoadEcdsaPrivateFromCertificateSecretAsync(secretClient, _clientEncKid, cancellationToken);
        _clientEncPriv = ToKeyAgreementCngKey(encEcdsa, includePrivate: true);

        // Gateway public keys: sig-{GatewayId}-{suffix} / enc-{GatewayId}-{suffix}
        var gwId = string.IsNullOrWhiteSpace(_options.GatewayId) ? "gateway" : _options.GatewayId.Trim();
        _gatewaySigKid = $"sig-{gwId}-{suffix}";
        _gatewayEncKid = $"enc-{gwId}-{suffix}";
        _gatewaySigPub = await LoadEcdsaPublicFromCertificateAsync(certClient, _gatewaySigKid, cancellationToken);
        _gatewayEncPub = await LoadCngPublicFromCertificateAsync(certClient, _gatewayEncKid, cancellationToken);

        lock (_sync)
        {
            _initialized = true;
        }
    }

    public ECDsa GetClientSigPrivate() => _clientSigPriv ?? throw new InvalidOperationException("Provider não inicializado.");
    public CngKey GetClientEncPrivate() => _clientEncPriv ?? throw new InvalidOperationException("Provider não inicializado.");
    public string GetClientSigKid() => _clientSigKid ?? throw new InvalidOperationException("Provider não inicializado.");
    public string GetClientEncKid() => _clientEncKid ?? throw new InvalidOperationException("Provider não inicializado.");
    public ECDsa GetGatewaySigPublic() => _gatewaySigPub ?? throw new InvalidOperationException("Provider não inicializado.");
    public CngKey GetGatewayEncPublic() => _gatewayEncPub ?? throw new InvalidOperationException("Provider não inicializado.");
    public string GetGatewaySigKid() => _gatewaySigKid ?? throw new InvalidOperationException("Provider não inicializado.");
    public string GetGatewayEncKid() => _gatewayEncKid ?? throw new InvalidOperationException("Provider não inicializado.");

    private static async Task<ECDsa> LoadEcdsaPrivateFromCertificateSecretAsync(
        SecretClient secretClient,
        string certificateName,
        CancellationToken cancellationToken)
    {
        var secret = await secretClient.GetSecretAsync(certificateName, cancellationToken: cancellationToken);
        var pfxBytes = Convert.FromBase64String(secret.Value.Value);
        var cert = new X509Certificate2(
            pfxBytes,
            (string?)null,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);

        return cert.GetECDsaPrivateKey()
               ?? throw new InvalidOperationException($"Certificado '{certificateName}' no KeyVault não contém chave privada ECDSA.");
    }

    private static async Task<ECDsa> LoadEcdsaPublicFromCertificateAsync(
        CertificateClient certClient,
        string certificateName,
        CancellationToken cancellationToken)
    {
        var certWithPolicy = await certClient.GetCertificateAsync(certificateName, cancellationToken);
        var cert = new X509Certificate2(certWithPolicy.Value.Cer);
        return cert.GetECDsaPublicKey()
               ?? throw new InvalidOperationException($"Certificado '{certificateName}' no KeyVault não contém chave pública ECDSA.");
    }

    private static async Task<CngKey> LoadCngPublicFromCertificateAsync(
        CertificateClient certClient,
        string certificateName,
        CancellationToken cancellationToken)
    {
        using var ecdsa = await LoadEcdsaPublicFromCertificateAsync(certClient, certificateName, cancellationToken);
        return ToKeyAgreementCngKey(ecdsa, includePrivate: false);
    }

    private static CngKey ToKeyAgreementCngKey(ECDsa ecdsa, bool includePrivate)
    {
        var p = ecdsa.ExportParameters(includePrivate);
        if (p.Q.X is null || p.Q.Y is null)
            throw new InvalidOperationException("Parâmetros EC inválidos (Q).");
        var d = includePrivate ? p.D : null;
        return EccKey.New(p.Q.X, p.Q.Y, d, usage: CngKeyUsages.KeyAgreement);
    }
}

