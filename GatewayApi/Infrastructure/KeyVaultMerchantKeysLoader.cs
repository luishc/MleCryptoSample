using Azure.Core;
using Azure.Security.KeyVault.Certificates;
using GatewayApi.Infrastructure.Abstractions;
using GatewayApi.Models;
using Jose.keys;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace GatewayApi.Infrastructure;

/// <summary>Carrega chaves públicas do cliente a partir de certificados EC no Azure Key Vault.</summary>
public sealed class KeyVaultMerchantKeysLoader
{
    private readonly TokenCredential _credential;
    private readonly GatewayKeyVaultOptions _keyVaultOptions;

    public KeyVaultMerchantKeysLoader(
        TokenCredential credential,
        IOptions<GatewayKeyVaultOptions> keyVaultOptions)
    {
        _credential = credential ?? throw new ArgumentNullException(nameof(credential));
        _keyVaultOptions = keyVaultOptions?.Value ?? throw new ArgumentNullException(nameof(keyVaultOptions));
    }

    public async Task LoadAsync(string merchantId, IClientKeyStore store)
    {
        if (string.IsNullOrWhiteSpace(merchantId))
            throw new ArgumentException("merchantId é obrigatório.", nameof(merchantId));

        if (string.IsNullOrWhiteSpace(_keyVaultOptions.Uri))
            throw new InvalidOperationException("Gateway:KeyVault:Uri é obrigatório quando algum merchant usa Source=KeyVault.");

        var suffix = _keyVaultOptions.CertificateVersionSuffix?.Trim();
        if (string.IsNullOrEmpty(suffix))
            throw new InvalidOperationException("Gateway:KeyVault:CertificateVersionSuffix é obrigatório (ex.: 2026-03).");

        var sigCertificateName = $"sig-{merchantId}-{suffix}";
        var encCertificateName = $"enc-{merchantId}-{suffix}";
        var sigKid = sigCertificateName;
        var encKid = encCertificateName;

        var certClient = new CertificateClient(new Uri(_keyVaultOptions.Uri), _credential);

        var sigResponse = await certClient.GetCertificateAsync(sigCertificateName);
        var encResponse = await certClient.GetCertificateAsync(encCertificateName);

        using var sigCert = new X509Certificate2(sigResponse.Value.Cer);
        using var encCert = new X509Certificate2(encResponse.Value.Cer);

        var sigEcdsa = CreateEcdsaPublicCopy(sigCert);
        var encCng = CreateEcdhPublicKey(encCert);

        var sigByKid = new Dictionary<string, ECDsa> { [sigKid] = sigEcdsa };
        var encByKid = new Dictionary<string, CngKey> { [encKid] = encCng };

        await store.MergeMerchantKeysAsync(merchantId, sigByKid, encByKid);
    }

    private static ECDsa CreateEcdsaPublicCopy(X509Certificate2 cert)
    {
        using var pub = cert.GetECDsaPublicKey();
        if (pub == null)
            throw new InvalidOperationException("O certificado de assinatura deve ser de curva elíptica (EC).");
        var p = pub.ExportParameters(false);
        return ECDsa.Create(p);
    }

    private static CngKey CreateEcdhPublicKey(X509Certificate2 cert)
    {
        using var pub = cert.GetECDsaPublicKey();
        if (pub == null)
            throw new InvalidOperationException("O certificado de criptografia deve ser de curva elíptica (EC).");
        var p = pub.ExportParameters(false);
        return EccKey.New(p.Q.X!, p.Q.Y!, d: null, usage: CngKeyUsages.KeyAgreement);
    }
}
