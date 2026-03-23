using GatewayApi.Models;
using Jose.keys;
using System.Security.Cryptography;

namespace GatewayApi.Infrastructure;

internal static class JwkSetKeyMaterial
{
    public static (Dictionary<string, ECDsa> SigByKid, Dictionary<string, CngKey> EncByKid) FromJwkSet(JwkSet jwks)
    {
        var sigKeys = jwks.Keys.Where(k => k.Use == "sig").ToList();
        var encKeys = jwks.Keys.Where(k => k.Use == "enc").ToList();
        if (sigKeys.Count == 0)
            throw new InvalidOperationException("JWKS não contém chave de assinatura (use='sig').");
        if (encKeys.Count == 0)
            throw new InvalidOperationException("JWKS não contém chave de criptografia (use='enc').");

        var jwsByKid = new Dictionary<string, ECDsa>();
        foreach (var k in sigKeys)
        {
            var p = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP384,
                Q = new ECPoint { X = Base64Url.Decode(k.X), Y = Base64Url.Decode(k.Y) }
            };
            jwsByKid[k.Kid] = ECDsa.Create(p);
        }

        var encByKid = new Dictionary<string, CngKey>();
        foreach (var k in encKeys)
        {
            var encX = Base64Url.Decode(k.X);
            var encY = Base64Url.Decode(k.Y);
            encByKid[k.Kid] = EccKey.New(encX, encY, d: null, usage: CngKeyUsages.KeyAgreement);
        }

        return (jwsByKid, encByKid);
    }
}
