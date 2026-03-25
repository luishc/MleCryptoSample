namespace ClientApi.Models;

public sealed class ClientKeyVaultOptions
{
    public string? Uri { get; set; }
    public string? CurrentCertificateVersionSuffix { get; set; }
    public string? PreviousCertificateVersionSuffix { get; set; }
    public string? CertificateVersionSuffix { get; set; } // backward compatibility
    public string GatewayId { get; set; } = "gateway";
}

