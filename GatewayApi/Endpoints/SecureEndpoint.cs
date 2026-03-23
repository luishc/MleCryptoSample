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

            // 1) Decriptar + validar assinatura do CLIENTE; obter kid do JWS para usar na resposta
            var (jsonPayload, clientSigKid) = crypto.Decrypt(
                token,
                gatewayKeys.GetEncPrivate(),
                kid => clientKeys.GetClientJwsPublic(merchantId, kid));

            // 2) Enviar JSON para App X
            var http = httpClientFactory.CreateClient();
            var resp = await http.PostAsync(
                appXUrl,
                new StringContent(jsonPayload, Encoding.UTF8, "application/json"));
            if (!resp.IsSuccessStatusCode)
                return Results.Problem($"Falha ao chamar aplicação X: {(int)resp.StatusCode}");
            var responseJson = await resp.Content.ReadAsStringAsync();

            // 3) Resposta: assinar com o gateway e criptografar para o cliente usando o mesmo key set (kid) do request
            var clientEncKid = clientKeys.DeriveEncKidFromSigKid(clientSigKid);
            var gatewaySigKid = gatewayKeys.GetCurrentSigKid();
            var responseToken = crypto.Encrypt(
                responseJson,
                gatewayKeys.GetJwsPrivate(),
                clientKeys.GetClientEncPublic(merchantId, clientEncKid),
                gatewaySigKid,
                clientEncKid);
            return Results.Text(responseToken, "application/jose");
        }
    }
}