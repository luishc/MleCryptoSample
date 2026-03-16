namespace ClientApi;

public sealed class GatewayJwksRefreshService : BackgroundService
{
    private readonly IServiceProvider _services;
    private readonly IConfiguration _configuration;
    private readonly ILogger<GatewayJwksRefreshService> _logger;

    public GatewayJwksRefreshService(
        IServiceProvider services,
        IConfiguration configuration,
        ILogger<GatewayJwksRefreshService> logger)
    {
        _services = services;
        _configuration = configuration;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Aguarda 1 dia antes da primeira atualização (a carga inicial já foi feita no startup).
        try
        {
            await Task.Delay(TimeSpan.FromDays(1), stoppingToken);
        }
        catch (TaskCanceledException)
        {
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            var discoveryUrl = _configuration["Client:GatewayDiscoveryUrl"];
            if (!string.IsNullOrWhiteSpace(discoveryUrl))
            {
                try
                {
                    using (var scope = _services.CreateScope())
                    {
                        var serverKeyStore = scope.ServiceProvider.GetRequiredService<IServerKeyStore>();
                        await serverKeyStore.EnsureInitializedAsync(discoveryUrl);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Falha na atualização diária das chaves JWKS do gateway. A aplicação continuará usando as chaves já carregadas.");
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

