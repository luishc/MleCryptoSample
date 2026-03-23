using System.Text;
using System.Text.Json;
using GatewayApi.Models;

namespace GatewayApi.Infrastructure.Helpers;

/// <summary>
/// Extrai o "kid" do header de um token JWT (JWS ou JWE) sem decodificar o payload.
/// </summary>
public static class JwtHeaderHelper
{
    public static string? GetKidFromToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token)) return null;
        var parts = token.Split('.');
        if (parts.Length < 2) return null;
        try
        {
            var headerJson = Encoding.UTF8.GetString(Base64Url.Decode(parts[0]));
            using var doc = JsonDocument.Parse(headerJson);
            if (doc.RootElement.TryGetProperty("kid", out var kidProp))
                return kidProp.GetString();
        }
        catch { /* ignore */ }
        return null;
    }
}
