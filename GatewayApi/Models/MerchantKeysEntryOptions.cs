namespace GatewayApi.Models;

/// <summary>
/// Configuração por MerchantId para carregar chaves públicas do cliente.
/// <list type="bullet">
/// <item><description><b>KeyVault</b>: URI em <c>Gateway:KeyVault</c>; sufixos por merchant em <see cref="CurrentCertificateVersionSuffix"/> e <see cref="PreviousCertificateVersionSuffix"/>.</description></item>
/// </list>
/// </summary>
public sealed class MerchantKeysEntryOptions
{
    /// <summary>KeyVault</summary>
    public string? Source { get; set; }

    /// <summary>Sufixo atual do merchant (ex.: 2026-04).</summary>
    public string? CurrentCertificateVersionSuffix { get; set; }

    /// <summary>Sufixo anterior do merchant para janela de rotação (ex.: 2026-03).</summary>
    public string? PreviousCertificateVersionSuffix { get; set; }
}
