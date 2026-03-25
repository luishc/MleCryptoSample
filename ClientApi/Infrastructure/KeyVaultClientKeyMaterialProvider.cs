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

    private readonly Dictionary<string, ECDsa> _clientSigPrivByKid = new();
    private readonly Dictionary<string, CngKey> _clientEncPrivByKid = new();
    private string? _clientSigKid;
    private string? _clientEncKid;

    private readonly Dictionary<string, ECDsa> _gatewaySigPubByKid = new();
    private readonly Dictionary<string, CngKey> _gatewayEncPubByKid = new();
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
        var currentSuffix = _options.CurrentCertificateVersionSuffix?.Trim();
        if (string.IsNullOrWhiteSpace(currentSuffix))
            currentSuffix = _options.CertificateVersionSuffix?.Trim(); // backwards compatibility
        if (string.IsNullOrWhiteSpace(currentSuffix))
            throw new InvalidOperationException("Client:KeyVault:CurrentCertificateVersionSuffix é obrigatório.");
        var previousSuffix = _options.PreviousCertificateVersionSuffix?.Trim();

        var vaultUri = new Uri(_options.Uri);
        var certClient = new CertificateClient(vaultUri, _credential);
        var secretClient = new SecretClient(vaultUri, _credential);

        // Client own private keys: sig-{MerchantId}-{suffix} / enc-{MerchantId}-{suffix}
        _clientSigKid = $"sig-{merchantId}-{currentSuffix}";
        _clientEncKid = $"enc-{merchantId}-{currentSuffix}";
        _clientSigPrivByKid[_clientSigKid] = await LoadEcdsaPrivateFromCertificateSecretAsync(secretClient, _clientSigKid, cancellationToken);
        using (var encEcdsa = await LoadEcdsaPrivateFromCertificateSecretAsync(secretClient, _clientEncKid, cancellationToken))
        {
            _clientEncPrivByKid[_clientEncKid] = ToKeyAgreementCngKey(encEcdsa, includePrivate: true);
        }

        if (!string.IsNullOrWhiteSpace(previousSuffix))
        {
            var prevClientSigKid = $"sig-{merchantId}-{previousSuffix}";
            var prevClientEncKid = $"enc-{merchantId}-{previousSuffix}";
            _clientSigPrivByKid[prevClientSigKid] = await LoadEcdsaPrivateFromCertificateSecretAsync(secretClient, prevClientSigKid, cancellationToken);
            using var prevEncEcdsa = await LoadEcdsaPrivateFromCertificateSecretAsync(secretClient, prevClientEncKid, cancellationToken);
            _clientEncPrivByKid[prevClientEncKid] = ToKeyAgreementCngKey(prevEncEcdsa, includePrivate: true);
        }

        // Gateway public keys: sig-{GatewayId}-{suffix} / enc-{GatewayId}-{suffix}
        var gwId = string.IsNullOrWhiteSpace(_options.GatewayId) ? "gateway" : _options.GatewayId.Trim();
        _gatewaySigKid = $"sig-{gwId}-{currentSuffix}";
        _gatewayEncKid = $"enc-{gwId}-{currentSuffix}";
        _gatewaySigPubByKid[_gatewaySigKid] = await LoadEcdsaPublicFromCertificateAsync(certClient, _gatewaySigKid, cancellationToken);
        _gatewayEncPubByKid[_gatewayEncKid] = await LoadCngPublicFromCertificateAsync(certClient, _gatewayEncKid, cancellationToken);

        if (!string.IsNullOrWhiteSpace(previousSuffix))
        {
            var prevGwSigKid = $"sig-{gwId}-{previousSuffix}";
            var prevGwEncKid = $"enc-{gwId}-{previousSuffix}";
            _gatewaySigPubByKid[prevGwSigKid] = await LoadEcdsaPublicFromCertificateAsync(certClient, prevGwSigKid, cancellationToken);
            _gatewayEncPubByKid[prevGwEncKid] = await LoadCngPublicFromCertificateAsync(certClient, prevGwEncKid, cancellationToken);
        }

        lock (_sync)
        {
            _initialized = true;
        }
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

