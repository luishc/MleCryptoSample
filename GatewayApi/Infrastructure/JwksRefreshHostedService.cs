using GatewayApi.Infrastructure.Abstractions;

namespace GatewayApi.Infrastructure;

public sealed class JwksRefreshHostedService : BackgroundService
{
    private readonly IServiceProvider _services;
    private readonly TimeSpan _refreshKeys;

    public JwksRefreshHostedService(
        IServiceProvider services,
        TimeSpan refreshKeys)
    {
        _services = services;
        _refreshKeys = refreshKeys;
    }

    protected override async Task ExecuteAsync(
        CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            //TODO: Implementar refresh de forma que se alguma atualização falhar, não quebrar a aplicação
            using (var scope = _services.CreateScope())
            {
                var discoverService = scope.ServiceProvider.GetRequiredService<IDiscoveryClientsPublicKeys>();
                await discoverService.InitAsync();
            }

            try
            {
                await Task.Delay(_refreshKeys, stoppingToken);
            }
            catch (TaskCanceledException)
            {
                break;
            }
        }
    }
}