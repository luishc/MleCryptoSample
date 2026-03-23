using GatewayApi.Infrastructure.Abstractions;
using GatewayApi.Models;

namespace GatewayApi.Infrastructure;

/// <summary>Carrega chaves do cliente a partir de um endpoint JWKS.</summary>
public sealed class JwksMerchantKeysLoader
{
    private readonly IHttpClientFactory _httpClientFactory;

    public JwksMerchantKeysLoader(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }

    public async Task LoadAsync(string merchantId, string discoveryUrl, IClientKeyStore store)
    {
        if (string.IsNullOrWhiteSpace(merchantId))
            throw new ArgumentException("merchantId é obrigatório.", nameof(merchantId));
        if (string.IsNullOrWhiteSpace(discoveryUrl))
            throw new ArgumentException("DiscoveryUrl é obrigatório.", nameof(discoveryUrl));

        var client = _httpClientFactory.CreateClient();
        var jwks = await client.GetFromJsonAsync<JwkSet>(discoveryUrl)
                   ?? throw new InvalidOperationException("JWKS do cliente inválido.");

        var (sigByKid, encByKid) = JwkSetKeyMaterial.FromJwkSet(jwks);
        await store.MergeMerchantKeysAsync(merchantId, sigByKid, encByKid);
    }
}
