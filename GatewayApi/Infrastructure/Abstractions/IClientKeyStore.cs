using System.Security.Cryptography;

namespace GatewayApi.Infrastructure.Abstractions
{
    public interface IClientKeyStore
    {
        /// <summary>Carrega o par de chaves públicas (sig/enc) ativo do cliente para o merchant.</summary>
        Task MergeMerchantKeysAsync(string merchantId, IReadOnlyDictionary<string, ECDsa> sigByKid, IReadOnlyDictionary<string, CngKey> encByKid);
        ECDsa GetClientJwsPublic(string merchantId, string kid);
        CngKey GetClientEncPublic(string merchantId, string kid);
        /// <summary>Deriva o enc kid do mesmo key set a partir do sig kid (ex: sig-2026-03 -> enc-2026-03).</summary>
        string DeriveEncKidFromSigKid(string sigKid);
    }
}