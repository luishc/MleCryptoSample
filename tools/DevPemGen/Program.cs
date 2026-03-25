using System.Security.Cryptography;
using System.Text.Json;

static string Pem(string label, byte[] bytes)
{
    var b64 = Convert.ToBase64String(bytes);
    var lines = Enumerable.Range(0, (b64.Length + 63) / 64)
        .Select(i => b64.Substring(i * 64, Math.Min(64, b64.Length - i * 64)));
    return $"-----BEGIN {label}-----\n{string.Join('\n', lines)}\n-----END {label}-----";
}

static (string privPem, string pubPem) GenP384Pkcs8()
{
    using var e = ECDsa.Create(ECCurve.NamedCurves.nistP384);
    var priv = Pem("PRIVATE KEY", e.ExportPkcs8PrivateKey());
    var pub = Pem("PUBLIC KEY", e.ExportSubjectPublicKeyInfo());
    return (priv, pub);
}

var (gwSigPriv, gwSigPub) = GenP384Pkcs8();
var (gwEncPriv, gwEncPub) = GenP384Pkcs8();
var (mSigPriv, mSigPub) = GenP384Pkcs8();
var (mEncPriv, mEncPub) = GenP384Pkcs8();

var obj = new
{
    gateway = new { sigPriv = gwSigPriv, sigPub = gwSigPub, encPriv = gwEncPriv, encPub = gwEncPub },
    merchant = new { sigPriv = mSigPriv, sigPub = mSigPub, encPriv = mEncPriv, encPub = mEncPub }
};

Console.WriteLine(JsonSerializer.Serialize(obj, new JsonSerializerOptions { WriteIndented = true }));

