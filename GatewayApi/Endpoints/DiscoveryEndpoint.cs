using GatewayApi.Infrastructure.Abstractions;
using GatewayApi.Models;
using Microsoft.AspNetCore.Mvc;

namespace GatewayApi.Endpoints
{
    public static class DiscoveryEndpoint
    {
        public static void MapDiscoveryEndpoints(
            this IEndpointRouteBuilder app)
        {
            app.MapGet("/discovery/keys", GetPublicKeys);
            app.MapGet("/.well-known/jwks.json", GetJwks);
            app.MapGet("/.well-known/jose-configuration", GetJoseConfiguration);
        }

        public static IResult GetPublicKeys(
            [FromServices] IServerOwnKeyStore keys)
        {
            var serverKeys = keys.GetDiscoveryKeys();
            return Results.Json(serverKeys);
        }

        public static IResult GetJwks(
            [FromServices] IServerOwnKeyStore keys)
        {
            var jwks = new JwkSet
            {
                Keys = keys.GetJwkKeys()
            };

            return Results.Json(jwks);
        }

        public static IResult GetJoseConfiguration(
            HttpRequest request)
        {
            var issuer = $"{request.Scheme}://{request.Host.Value}";

            var config = new
            {
                issuer,
                jwks_uri = $"{issuer}/.well-known/jwks.json",
                jws_algs_supported = new[] { "ES384" },
                jwe_algs_supported = new[] { "ECDH-ES" },
                jwe_encs_supported = new[] { "A256GCM" }
            };

            return Results.Json(config);
        }
    }
}