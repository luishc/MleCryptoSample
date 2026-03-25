using Azure.Core;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using GatewayApi.Infrastructure.Abstractions;
using GatewayApi.Models;
using Jose.keys;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace GatewayApi.Infrastructure;

public sealed class KeyVaultKeyMaterialProvider : IKeyMaterialProvider
{
    private readonly TokenCredential _credential;
    private readonly GatewayKeyVaultOptions _options;
    private readonly IConfiguration _configuration;

    private bool _initialized;
    private readonly object _sync = new();

    private ECDsa? _gatewaySigPriv;
    private CngKey? _gatewayEncPriv;
    private string? _gatewaySigKid;
    private string? _gatewayEncKid;

    private readonly Dictionary<string, (ECDsa Sig, CngKey Enc, string SigKid, string EncKid)> _clientByMerchant = new();

    public KeyVaultKeyMaterialProvider(
        TokenCredential credential,
        IOptions<GatewayKeyVaultOptions> options,
        IConfiguration configuration)
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

        if (string.IsNullOrWhiteSpace(_options.Uri))
            throw new InvalidOperationException("Gateway:KeyVault:Uri é obrigatório.");
        var suffix = _options.CertificateVersionSuffix?.Trim();
        if (string.IsNullOrWhiteSpace(suffix))
            throw new InvalidOperationException("Gateway:KeyVault:CertificateVersionSuffix é obrigatório.");

        var vaultUri = new Uri(_options.Uri);
        var certClient = new CertificateClient(vaultUri, _credential);
        var secretClient = new SecretClient(vaultUri, _credential);

        // Gateway own private keys come from KV secrets (PFX)
        var gwId = string.IsNullOrWhiteSpace(_options.GatewayId) ? "gateway" : _options.GatewayId.Trim();
        _gatewaySigKid = $"sig-{gwId}-{suffix}";
        _gatewayEncKid = $"enc-{gwId}-{suffix}";

        _gatewaySigPriv = await LoadEcdsaPrivateFromCertificateSecretAsync(secretClient, _gatewaySigKid, cancellationToken);
        using var gwEncEcdsa = await LoadEcdsaPrivateFromCertificateSecretAsync(secretClient, _gatewayEncKid, cancellationToken);
        _gatewayEncPriv = ToKeyAgreementCngKey(gwEncEcdsa, includePrivate: true);

        // Merchants list comes from Gateway:Merchants keys; Source must be KeyVault
        var merchantsSection = _configuration.GetSection("Gateway:Merchants");
        var merchantIds = merchantsSection.GetChildren().Select(c => c.Key).Where(k => !string.IsNullOrWhiteSpace(k)).ToList();
        if (merchantIds.Count == 0)
            throw new InvalidOperationException("Configure pelo menos um merchant em Gateway:Merchants.");

        foreach (var merchantId in merchantIds)
        {
            var entry = merchantsSection.GetSection(merchantId).Get<MerchantKeysEntryOptions>();
            if (entry is null || !string.Equals(entry.Source?.Trim(), "KeyVault", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException($"Gateway:Merchants:{merchantId}: apenas Source=KeyVault é suportado.");

            var clientSigKid = $"sig-{merchantId}-{suffix}";
            var clientEncKid = $"enc-{merchantId}-{suffix}";
            var sigPub = await LoadEcdsaPublicFromCertificateAsync(certClient, clientSigKid, cancellationToken);
            var encPub = await LoadCngPublicFromCertificateAsync(certClient, clientEncKid, cancellationToken);
            _clientByMerchant[merchantId] = (sigPub, encPub, clientSigKid, clientEncKid);
        }

        lock (_sync)
        {
            _initialized = true;
        }
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
        throw new InvalidOperationException($"Merchant '{merchantId}' não carregado.");
    }

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

