namespace GatewayApi.Models;

/// <summary>
/// Configuração por MerchantId para carregar chaves públicas do cliente.
/// <list type="bullet">
/// <item><description><b>Discovery</b>: use <see cref="DiscoveryUrl"/> (JWKS).</description></item>
/// <item><description><b>KeyVault</b>: URI e sufixo em <c>Gateway:KeyVault</c>; certificados <c>sig-{MerchantId}-{suffix}</c> e <c>enc-{MerchantId}-{suffix}</c> (mesmos valores como <c>kid</c>).</description></item>
/// </list>
/// </summary>
public sealed class MerchantKeysEntryOptions
{
    /// <summary>Discovery | KeyVault</summary>
    public string? Source { get; set; }

    /// <summary>URL do JWKS quando <see cref="Source"/> = Discovery.</summary>
    public string? DiscoveryUrl { get; set; }
}
