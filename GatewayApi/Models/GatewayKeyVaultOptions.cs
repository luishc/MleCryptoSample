namespace GatewayApi.Models;

/// <summary>
/// Configuração global do Azure Key Vault para merchants com <see cref="MerchantKeysEntryOptions.Source"/> = KeyVault.
/// Nomes dos certificados: <c>sig-{MerchantId}-{CertificateVersionSuffix}</c> e <c>enc-{MerchantId}-{CertificateVersionSuffix}</c>.
/// </summary>
public sealed class GatewayKeyVaultOptions
{
    /// <summary>URI do vault (ex.: https://meu-vault.vault.azure.net/).</summary>
    public string? Uri { get; set; }

    /// <summary>Sufixo de versão dos certificados (ex.: 2026-03).</summary>
    public string? CertificateVersionSuffix { get; set; }
}
