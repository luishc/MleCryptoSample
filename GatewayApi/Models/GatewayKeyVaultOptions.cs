namespace GatewayApi.Models;

/// <summary>
/// Configuração global do Azure Key Vault para merchants com <see cref="MerchantKeysEntryOptions.Source"/> = KeyVault.
/// Nomes dos certificados: <c>sig-{MerchantId}-{suffix}</c> e <c>enc-{MerchantId}-{suffix}</c>.
/// </summary>
public sealed class GatewayKeyVaultOptions
{
    /// <summary>URI do vault (ex.: https://meu-vault.vault.azure.net/).</summary>
    public string? Uri { get; set; }

    /// <summary>
    /// Sufixo atual global (legado) para certificados dos merchants.
    /// Prefira configurar por merchant em Gateway:Merchants:{merchantId}:CurrentCertificateVersionSuffix.
    /// </summary>
    public string? CurrentCertificateVersionSuffix { get; set; }

    /// <summary>
    /// Sufixo anterior global (legado) para certificados dos merchants.
    /// Prefira configurar por merchant em Gateway:Merchants:{merchantId}:PreviousCertificateVersionSuffix.
    /// </summary>
    public string? PreviousCertificateVersionSuffix { get; set; }

    /// <summary>
    /// Compatibilidade retroativa: se preenchido e Current não estiver definido, este valor será usado como current.
    /// </summary>
    public string? CertificateVersionSuffix { get; set; }

    /// <summary>Sufixo atual dos certificados do próprio gateway (ex.: 2026-04).</summary>
    public string? GatewayCurrentCertificateVersionSuffix { get; set; }

    /// <summary>Sufixo anterior dos certificados do gateway para janela de rotação (ex.: 2026-03).</summary>
    public string? GatewayPreviousCertificateVersionSuffix { get; set; }

    /// <summary>
    /// Identificador do gateway para nomear seus próprios certificados no vault.
    /// Ex.: sig-{GatewayId}-{suffix}, enc-{GatewayId}-{suffix}
    /// </summary>
    public string GatewayId { get; set; } = "gateway";
}
