namespace ClientApi.Models;

public sealed class ClientKeyVaultOptions
{
    public string? Uri { get; set; }
    public string? CertificateVersionSuffix { get; set; }
    public string GatewayId { get; set; } = "gateway";
}

