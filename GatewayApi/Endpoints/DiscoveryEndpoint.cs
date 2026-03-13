using GatewayApi.Infrastructure.Abstractions;
using Microsoft.AspNetCore.Mvc;

namespace GatewayApi.Endpoints
{
    public static class DiscoveryEndpoint
    {
        public static void MapDiscoveryEndpoints(
            this IEndpointRouteBuilder app)
        {
            app.MapGet("/discovery/keys", GetPublicKeys);
        }

        public static IResult GetPublicKeys(
            [FromServices] IServerOwnKeyStore keys)
        {
            var serverKeys = keys.GetDiscoveryKeys();
            return Results.Json(serverKeys);
        }
    }
}