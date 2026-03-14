namespace ClientApi;

public sealed class GatewayJwksRefreshService : BackgroundService
{
    private readonly IServiceProvider _services;
    private readonly IConfiguration _configuration;

    public GatewayJwksRefreshService(IServiceProvider services, IConfiguration configuration)
    {
        _services = services;
        _configuration = configuration;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            using (var scope = _services.CreateScope())
            {
                var serverKeyStore = scope.ServiceProvider.GetRequiredService<IServerKeyStore>();
                var discoveryUrl = _configuration["Client:GatewayDiscoveryUrl"];
                if (!string.IsNullOrWhiteSpace(discoveryUrl))
                {
                    await serverKeyStore.EnsureInitializedAsync(discoveryUrl);
                }
            }

            try
            {
                await Task.Delay(TimeSpan.FromDays(1), stoppingToken);
            }
            catch (TaskCanceledException)
            {
                break;
            }
        }
    }
}

