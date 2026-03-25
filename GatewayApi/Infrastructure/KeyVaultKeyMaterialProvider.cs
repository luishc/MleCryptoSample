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

    private readonly Dictionary<string, ECDsa> _gatewaySigPrivByKid = new();
    private readonly Dictionary<string, CngKey> _gatewayEncPrivByKid = new();
    private string? _gatewaySigKid;
    private string? _gatewayEncKid;

    private readonly Dictionary<string, Dictionary<string, ECDsa>> _clientSigByMerchantAndKid = new();
    private readonly Dictionary<string, Dictionary<string, CngKey>> _clientEncByMerchantAndKid = new();

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
        var globalCurrentSuffix = _options.CurrentCertificateVersionSuffix?.Trim();
        if (string.IsNullOrWhiteSpace(globalCurrentSuffix))
            globalCurrentSuffix = _options.CertificateVersionSuffix?.Trim(); // backwards compatibility
        var globalPreviousSuffix = _options.PreviousCertificateVersionSuffix?.Trim();

        var gatewayCurrentSuffix = _options.GatewayCurrentCertificateVersionSuffix?.Trim();
        if (string.IsNullOrWhiteSpace(gatewayCurrentSuffix))
            gatewayCurrentSuffix = globalCurrentSuffix;
        if (string.IsNullOrWhiteSpace(gatewayCurrentSuffix))
            throw new InvalidOperationException("Gateway:KeyVault:GatewayCurrentCertificateVersionSuffix é obrigatório.");
        var gatewayPreviousSuffix = _options.GatewayPreviousCertificateVersionSuffix?.Trim();
        if (string.IsNullOrWhiteSpace(gatewayPreviousSuffix))
            gatewayPreviousSuffix = globalPreviousSuffix;

        var vaultUri = new Uri(_options.Uri);
        var certClient = new CertificateClient(vaultUri, _credential);
        var secretClient = new SecretClient(vaultUri, _credential);

        // Gateway own private keys come from KV secrets (PFX)
        var gwId = string.IsNullOrWhiteSpace(_options.GatewayId) ? "gateway" : _options.GatewayId.Trim();
        _gatewaySigKid = $"sig-{gwId}-{gatewayCurrentSuffix}";
        _gatewayEncKid = $"enc-{gwId}-{gatewayCurrentSuffix}";

        _gatewaySigPrivByKid[_gatewaySigKid] = await LoadEcdsaPrivateFromCertificateSecretAsync(secretClient, _gatewaySigKid, cancellationToken);
        using (var gwEncEcdsa = await LoadEcdsaPrivateFromCertificateSecretAsync(secretClient, _gatewayEncKid, cancellationToken))
        {
            _gatewayEncPrivByKid[_gatewayEncKid] = ToKeyAgreementCngKey(gwEncEcdsa, includePrivate: true);
        }

        if (!string.IsNullOrWhiteSpace(gatewayPreviousSuffix))
        {
            var prevGwSigKid = $"sig-{gwId}-{gatewayPreviousSuffix}";
            var prevGwEncKid = $"enc-{gwId}-{gatewayPreviousSuffix}";
            _gatewaySigPrivByKid[prevGwSigKid] = await LoadEcdsaPrivateFromCertificateSecretAsync(secretClient, prevGwSigKid, cancellationToken);
            using var prevGwEncEcdsa = await LoadEcdsaPrivateFromCertificateSecretAsync(secretClient, prevGwEncKid, cancellationToken);
            _gatewayEncPrivByKid[prevGwEncKid] = ToKeyAgreementCngKey(prevGwEncEcdsa, includePrivate: true);
        }

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

            var merchantCurrentSuffix = entry.CurrentCertificateVersionSuffix?.Trim();
            if (string.IsNullOrWhiteSpace(merchantCurrentSuffix))
                merchantCurrentSuffix = globalCurrentSuffix;
            if (string.IsNullOrWhiteSpace(merchantCurrentSuffix))
                throw new InvalidOperationException($"Gateway:Merchants:{merchantId}: CurrentCertificateVersionSuffix é obrigatório.");
            var merchantPreviousSuffix = entry.PreviousCertificateVersionSuffix?.Trim();
            if (string.IsNullOrWhiteSpace(merchantPreviousSuffix))
                merchantPreviousSuffix = globalPreviousSuffix;

            var sigByKid = new Dictionary<string, ECDsa>();
            var encByKid = new Dictionary<string, CngKey>();

            var clientSigKid = $"sig-{merchantId}-{merchantCurrentSuffix}";
            var clientEncKid = $"enc-{merchantId}-{merchantCurrentSuffix}";
            sigByKid[clientSigKid] = await LoadEcdsaPublicFromCertificateAsync(certClient, clientSigKid, cancellationToken);
            encByKid[clientEncKid] = await LoadCngPublicFromCertificateAsync(certClient, clientEncKid, cancellationToken);

            if (!string.IsNullOrWhiteSpace(merchantPreviousSuffix))
            {
                var prevSigKid = $"sig-{merchantId}-{merchantPreviousSuffix}";
                var prevEncKid = $"enc-{merchantId}-{merchantPreviousSuffix}";
                sigByKid[prevSigKid] = await LoadEcdsaPublicFromCertificateAsync(certClient, prevSigKid, cancellationToken);
                encByKid[prevEncKid] = await LoadCngPublicFromCertificateAsync(certClient, prevEncKid, cancellationToken);
            }

            _clientSigByMerchantAndKid[merchantId] = sigByKid;
            _clientEncByMerchantAndKid[merchantId] = encByKid;
        }

        lock (_sync)
        {
            _initialized = true;
        }
    }

    public ECDsa GetGatewaySigPrivate()
    {
        if (!_initialized) throw new InvalidOperationException("Provider não inicializado.");
        return _gatewaySigPrivByKid[_gatewaySigKid ?? throw new InvalidOperationException("Provider não inicializado.")];
    }

    public CngKey GetGatewayEncPrivate(string kid)
    {
        if (!_initialized) throw new InvalidOperationException("Provider não inicializado.");
        if (_gatewayEncPrivByKid.TryGetValue(kid, out var key)) return key;
        throw new InvalidOperationException($"Chave privada ECDH do gateway para kid '{kid}' não encontrada.");
    }

    public string GetGatewaySigKid() => _gatewaySigKid ?? throw new InvalidOperationException("Provider não inicializado.");
    public string GetGatewayEncKid() => _gatewayEncKid ?? throw new InvalidOperationException("Provider não inicializado.");

    public IReadOnlyDictionary<string, ECDsa> GetClientSigPublicByKid(string merchantId)
    {
        if (!_initialized) throw new InvalidOperationException("Provider não inicializado.");
        if (_clientSigByMerchantAndKid.TryGetValue(merchantId, out var byKid)) return byKid;
        throw new InvalidOperationException($"Merchant '{merchantId}' não carregado.");
    }

    public IReadOnlyDictionary<string, CngKey> GetClientEncPublicByKid(string merchantId)
    {
        if (!_initialized) throw new InvalidOperationException("Provider não inicializado.");
        if (_clientEncByMerchantAndKid.TryGetValue(merchantId, out var byKid)) return byKid;
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

