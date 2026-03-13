using GatewayApi.Infrastructure.Abstractions;
using GatewayApi.Services;
using GatewayApi.Services.Abstractions;

namespace GatewayApi.Infrastructure.Modules
{
    public static class AppModule
    {
        public static void AddAppModule(
            this IServiceCollection services,
            IConfiguration configuration)
        {
            services.AddSingleton<IServerOwnKeyStore, ServerOwnKeyStore>();
            services.AddSingleton<IClientKeyStore, ClientKeyStore>();
            services.AddSingleton<ICryptoService, CryptoService>();

            services.AddScoped<IDiscoveryClientsPublicKeys>(c =>
                new DiscoveryClientsPublicKeys(
                    configuration,
                    c.GetRequiredService<IClientKeyStore>()));
        }
    }
}