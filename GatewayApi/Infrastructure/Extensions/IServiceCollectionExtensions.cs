using GatewayApi.Infrastructure.Modules;

namespace GatewayApi.Infrastructure.Extensions
{
    public static class IServiceCollectionExtensions
    {
        public static void ConfigureModules(
            this IServiceCollection services,
            IConfiguration configuration)
        {
            services.Configure<GatewayOptions>(configuration.GetSection("Gateway"));

            services.AddAppModule(configuration);
        }
    }
}