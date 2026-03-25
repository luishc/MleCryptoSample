namespace GatewayApi.Models;

/// <summary>
/// Configuração por MerchantId para carregar chaves públicas do cliente.
/// <list type="bullet">
/// <item><description><b>KeyVault</b>: URI e sufixo em <c>Gateway:KeyVault</c>; certificados <c>sig-{MerchantId}-{suffix}</c> e <c>enc-{MerchantId}-{suffix}</c> (mesmos valores como <c>kid</c>).</description></item>
/// </list>
/// </summary>
public sealed class MerchantKeysEntryOptions
{
    /// <summary>KeyVault</summary>
    public string? Source { get; set; }
}
