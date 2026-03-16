using GatewayApi.Infrastructure.Abstractions;

namespace GatewayApi.Infrastructure;

public sealed class JwksRefreshHostedService : BackgroundService
{
    private readonly IServiceProvider _services;
    private readonly TimeSpan _refreshInterval;
    private readonly ILogger<JwksRefreshHostedService> _logger;

    public JwksRefreshHostedService(
        IServiceProvider services,
        TimeSpan refreshInterval,
        ILogger<JwksRefreshHostedService> logger)
    {
        _services = services;
        _refreshInterval = refreshInterval;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Aguarda o intervalo antes da primeira atualização (a carga inicial já foi feita no startup).
        try
        {
            await Task.Delay(_refreshInterval, stoppingToken);
        }
        catch (TaskCanceledException)
        {
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using (var scope = _services.CreateScope())
                {
                    var discoverService = scope.ServiceProvider.GetRequiredService<IDiscoveryClientsPublicKeys>();
                    await discoverService.InitAsync();
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Falha na atualização diária das chaves JWKS dos clientes. A aplicação continuará usando as chaves já carregadas.");
            }

            try
            {
                await Task.Delay(_refreshInterval, stoppingToken);
            }
            catch (TaskCanceledException)
            {
                break;
            }
        }
    }
}