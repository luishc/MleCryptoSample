using GatewayApi.Services.Abstractions;
using Jose;
using System.Security.Cryptography;

namespace GatewayApi.Services
{
    public sealed class CryptoService : ICryptoService
    {
        public string Encrypt(string jsonPayload, ECDsa signingPrivateKey, CngKey receiverEncPublic)
        {
            var jws = JWT.Encode(jsonPayload, signingPrivateKey, JwsAlgorithm.ES384);

            var jwe = JWT.Encode(
                jws,
                receiverEncPublic,
                JweAlgorithm.ECDH_ES_A256KW,
                JweEncryption.A256GCM);

            return jwe;
        }

        public string Decrypt(string token, CngKey ownEncPrivate, ECDsa senderJwsPublic)
        {
            var jws = JWT.Decode(
                token,
                ownEncPrivate,
                JweAlgorithm.ECDH_ES_A256KW,
                JweEncryption.A256GCM);

            var json = JWT.Decode(
                jws,
                senderJwsPublic,
                JwsAlgorithm.ES384);

            return json;
        }
    }
}