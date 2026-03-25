namespace GatewayApi.Infrastructure.Abstractions;

public interface IKeyInitializer
{
    Task InitAsync(CancellationToken cancellationToken = default);
}

