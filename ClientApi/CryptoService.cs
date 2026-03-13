using Jose;
using System.Security.Cryptography;

namespace ClientApi
{
    public sealed class CryptoService
    {
        // Cria JWS ES384 + JWE ECDH-ES+A256GCM
        public string Protect(
            string jsonPayload,
            ECDsa signingPrivateKey, // do remetente
            CngKey receiverEncPublic // do destinatário
        )
        {
            // 1) JWS (assinatura ES384)
            var jws = JWT.Encode(jsonPayload, signingPrivateKey, JwsAlgorithm.ES384);
            // 2) JWE (ECDH-ES+A256KW / A256GCM)
            var jwe = JWT.Encode(
                jws,
                receiverEncPublic,
                JweAlgorithm.ECDH_ES_A256KW,
                JweEncryption.A256GCM);
            return jwe;
        }
        // Valida JWE+JWS (ordem inversa)
        public string Unprotect(
            string token,
            CngKey ownEncPrivate,      // privado do destinatário
            ECDsa senderJwsPublic      // público do remetente
        )
        {
            // 1) JWE → obtém o JWS
            var jws = JWT.Decode(
                token,
                ownEncPrivate,
                JweAlgorithm.ECDH_ES_A256KW,
                JweEncryption.A256GCM);
            // 2) JWS → obtém o JSON e valida ES384
            var json = JWT.Decode(
                jws,
                senderJwsPublic,
                JwsAlgorithm.ES384);
            return json;
        }
    }
}