using Azure.Core;
using Azure.Identity;
using GatewayApi.Infrastructure.Abstractions;
using GatewayApi.Models;
using GatewayApi.Services;
using GatewayApi.Services.Abstractions;
using Microsoft.Extensions.Options;

namespace GatewayApi.Infrastructure.Modules
{
    public static class AppModule
    {
        public static void AddAppModule(
            this IServiceCollection services,
            IConfiguration configuration)
        {
            services.Configure<GatewayKeyVaultOptions>(configuration.GetSection("Gateway:KeyVault"));
            services.Configure<LocalKeysOptions>(configuration.GetSection("Gateway:LocalKeys"));

            services.AddSingleton<IServerOwnKeyStore, ServerOwnKeyStore>();
            services.AddSingleton<IClientKeyStore, ClientKeyStore>();
            services.AddSingleton<ICryptoService, CryptoService>();

            services.AddSingleton<TokenCredential>(_ => new DefaultAzureCredential());

            services.AddSingleton<IKeyMaterialProvider>(sp =>
            {
                var mode = configuration["Gateway:KeyManagement:Mode"]?.Trim();
                if (string.Equals(mode, "Local", StringComparison.OrdinalIgnoreCase))
                    return new LocalAppsettingsKeyMaterialProvider(sp.GetRequiredService<IOptions<LocalKeysOptions>>());
                // default: KeyVault
                return new KeyVaultKeyMaterialProvider(
                    sp.GetRequiredService<TokenCredential>(),
                    sp.GetRequiredService<IOptions<GatewayKeyVaultOptions>>(),
                    configuration);
            });

            services.AddScoped<IKeyInitializer, KeyInitializer>();
        }
    }
}