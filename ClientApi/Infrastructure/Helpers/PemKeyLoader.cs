using Jose.keys;
using System.Security.Cryptography;

namespace ClientApi.Infrastructure.Helpers;

internal static class PemKeyLoader
{
    public static ECDsa LoadEcdsaFromPem(string pem)
    {
        if (string.IsNullOrWhiteSpace(pem))
            throw new ArgumentException("PEM obrigatório.", nameof(pem));

        var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(pem);
        return ecdsa;
    }

    public static CngKey ToKeyAgreementCngKey(ECDsa ecdsa, bool includePrivate)
    {
        var p = ecdsa.ExportParameters(includePrivate);
        if (p.Q.X is null || p.Q.Y is null)
            throw new InvalidOperationException("Parâmetros EC inválidos (Q).");
        var d = includePrivate ? p.D : null;
        return EccKey.New(p.Q.X, p.Q.Y, d, usage: CngKeyUsages.KeyAgreement);
    }
}

