using System.Security.Cryptography;

namespace GatewayApi.Services.Abstractions
{
    public interface ICryptoService
    {
        string Encrypt(string jsonPayload, ECDsa signingPrivateKey, CngKey receiverEncPublic);
        string Decrypt(string token, CngKey ownEncPrivate, ECDsa senderJwsPublic);
    }
}