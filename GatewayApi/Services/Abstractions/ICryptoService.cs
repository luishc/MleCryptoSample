using System.Security.Cryptography;

namespace GatewayApi.Services.Abstractions
{
    public interface ICryptoService
    {
        string Encrypt(string jsonPayload, ECDsa signingPrivateKey, CngKey receiverEncPublic, string sigKid, string encKid);
        (string Payload, string SenderSigKid) Decrypt(string token, CngKey ownEncPrivate, Func<string, ECDsa> getSenderJwsPublicByKid);
    }
}