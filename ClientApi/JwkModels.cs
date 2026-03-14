using System.Security.Cryptography;

namespace ClientApi;

public sealed class JwkKey
{
    public required string Kty { get; init; }
    public required string Use { get; init; }
    public required string Kid { get; init; }
    public required string Crv { get; init; }
    public required string Alg { get; init; }
    public required string X { get; init; }
    public required string Y { get; init; }
}

public sealed class JwkSet
{
    public required IReadOnlyCollection<JwkKey> Keys { get; init; }
}

internal static class Base64Url
{
    public static string Encode(byte[] bytes)
    {
        var s = Convert.ToBase64String(bytes);
        s = s.TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return s;
    }

    public static byte[] Decode(string s)
    {
        s = s.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }
        return Convert.FromBase64String(s);
    }
}

