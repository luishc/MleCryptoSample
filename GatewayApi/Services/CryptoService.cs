using GatewayApi.Infrastructure.Helpers;
using GatewayApi.Models;
using GatewayApi.Services.Abstractions;
using Jose;
using System.Security.Cryptography;

namespace GatewayApi.Services
{
    public sealed class CryptoService : ICryptoService
    {
        public string Encrypt(string jsonPayload, ECDsa signingPrivateKey, CngKey receiverEncPublic, string sigKid, string encKid)
        {
            var jwsHeaders = new Dictionary<string, object> { ["kid"] = sigKid };
            var jws = JWT.Encode(jsonPayload, signingPrivateKey, JwsAlgorithm.ES384, extraHeaders: jwsHeaders);

            var jweHeaders = new Dictionary<string, object> { ["kid"] = encKid };
            var jwe = JWT.Encode(
                jws,
                receiverEncPublic,
                JweAlgorithm.ECDH_ES_A256KW,
                JweEncryption.A256GCM,
                extraHeaders: jweHeaders);

            return jwe;
        }

        public (string Payload, string SenderSigKid) Decrypt(string token, CngKey ownEncPrivate, Func<string, ECDsa> getSenderJwsPublicByKid)
        {
            var jws = JWT.Decode(
                token,
                ownEncPrivate,
                JweAlgorithm.ECDH_ES_A256KW,
                JweEncryption.A256GCM);

            var sigKid = JwtHeaderHelper.GetKidFromToken(jws)
                         ?? throw new InvalidOperationException("Token JWS interno não contém 'kid' no header.");
            var senderJwsPublic = getSenderJwsPublicByKid(sigKid);

            var json = JWT.Decode(
                jws,
                senderJwsPublic,
                JwsAlgorithm.ES384);

            return (json, sigKid);
        }
    }
}