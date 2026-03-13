namespace GatewayApi.Models
{
    public sealed class DiscoveryKeysDto
    {
        // JWS (ES384) – chave pública em SubjectPublicKeyInfo (Base64)
        public required string JwsPublicKey { get; init; }

        // JWE (ECDH-ES) – coordenadas públicas da curva para ECDH (Base64)
        public required string EncX { get; init; }

        public required string EncY { get; init; }
    }
}