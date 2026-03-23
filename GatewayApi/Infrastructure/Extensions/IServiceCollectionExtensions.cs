using GatewayApi.Infrastructure.Modules;
using GatewayApi.Models;

namespace GatewayApi.Infrastructure.Extensions
{
    public static class IServiceCollectionExtensions
    {
        public static void ConfigureModules(
            this IServiceCollection services,
            IConfiguration configuration)
        {
            services.Configure<GatewayOptions>(configuration.GetSection("Gateway"));
            services.Configure<GatewayKeyVaultOptions>(configuration.GetSection("Gateway:KeyVault"));
            services.AddHostedService(provider =>
                new JwksRefreshHostedService(
                    provider,
                    TimeSpan.FromDays(1),
                    provider.GetRequiredService<Microsoft.Extensions.Logging.ILogger<JwksRefreshHostedService>>()));

            services.AddAppModule(configuration);
        }
    }
}