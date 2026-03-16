using GatewayApi.Infrastructure.Abstractions;
using GatewayApi.Services.Abstractions;
using Microsoft.AspNetCore.Mvc;
using System.Text;

namespace GatewayApi.Endpoints
{
    public static class SecureEndpoint
    {
        public static void MapSecureEndpoints(
            this IEndpointRouteBuilder app)
        {
            app.MapPost("/secure/process", Process);
        }

        public static async Task<IResult> Process(
            HttpRequest request,
            [FromHeader(Name = "MerchantId")] string merchantId,
            IServerOwnKeyStore gatewayKeys,
            IClientKeyStore clientKeys,
            ICryptoService crypto,
            IHttpClientFactory httpClientFactory,
            IConfiguration config)
        {
            using var reader = new StreamReader(request.Body, Encoding.UTF8);
            var token = await reader.ReadToEndAsync();
            if (string.IsNullOrWhiteSpace(token))
                return Results.Problem("Corpo da requisição vazio ou inválido.", statusCode: StatusCodes.Status400BadRequest);

            var appXUrl = config["Gateway:AppXUrl"];
            
            // 1) Decriptar + validar assinatura do CLIENTE
            var jsonPayload = crypto.Decrypt(
                token,
                gatewayKeys.GetEncPrivate(),          // privada ECDH do gateway
                clientKeys.GetClientJwsPublic(merchantId));     // pública ES384 do cliente
                                                                // 2) Enviar JSON para App X
            var http = httpClientFactory.CreateClient();
            var resp = await http.PostAsync(
                appXUrl,
                new StringContent(jsonPayload, Encoding.UTF8, "application/json"));
            if (!resp.IsSuccessStatusCode)
                return Results.Problem($"Falha ao chamar aplicação X: {(int)resp.StatusCode}");
            var responseJson = await resp.Content.ReadAsStringAsync();
            // 3) Assina como GATEWAY e criptografa para CLIENTE
            var responseToken = crypto.Encrypt(
                responseJson,
                gatewayKeys.GetJwsPrivate(),          // privada ES384 do gateway
                clientKeys.GetClientEncPublic(merchantId));     // pública ECDH do cliente
            return Results.Text(responseToken, "application/jose");
        }
    }
}