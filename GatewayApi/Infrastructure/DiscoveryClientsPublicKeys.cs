using GatewayApi.Infrastructure.Abstractions;

namespace GatewayApi.Infrastructure
{
    public class DiscoveryClientsPublicKeys : IDiscoveryClientsPublicKeys
    {
        public IConfiguration Configuration { get; }
        public IClientKeyStore ClientKeyStore { get; }

        public DiscoveryClientsPublicKeys(
            IConfiguration configuration,
            IClientKeyStore clientKeyStore)
        {
            Configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            ClientKeyStore = clientKeyStore ?? throw new ArgumentNullException(nameof(clientKeyStore));
        }

        public async Task InitAsync()
        {
            // Discovery de todos os clientes no startup.
            var discoverySection = Configuration.GetSection("Gateway:ClientDiscovery");

            foreach (var child in discoverySection.GetChildren())
            {
                var merchantId = child.Key;
                var discoveryUrl = child.Value;
                if (string.IsNullOrWhiteSpace(merchantId) || string.IsNullOrWhiteSpace(discoveryUrl))
                {
                    throw new InvalidOperationException("Configuração de Gateway:ClientDiscovery inválida (merchantId ou URL vazios).");
                }

                // Se qualquer discovery falhar, a aplicação não sobe.
                await ClientKeyStore.EnsureInitializedAsync(merchantId, discoveryUrl);
            }
        }
    }
}