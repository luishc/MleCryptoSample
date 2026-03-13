using GatewayApi;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddHttpClient();

builder.Services.AddSingleton<ServerOwnKeyStore>();
builder.Services.AddSingleton<ClientKeyStore>();
builder.Services.AddSingleton<CryptoService>();

builder.Services.Configure<GatewayOptions>(builder.Configuration.GetSection("Gateway"));

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.MapGet("/discovery/keys", ([FromServices] ServerOwnKeyStore keys) =>
{
    var serverKeys = keys.GetDiscoveryKeys();
    return Results.Json(serverKeys);
});

app.MapPost("/secure/process", async (
    HttpRequest request,
    [FromHeader(Name = "MerchantId")] string merchantId,
    ServerOwnKeyStore gatewayKeys,
    ClientKeyStore clientKeys,
    CryptoService crypto,
    IHttpClientFactory httpClientFactory,
    IConfiguration config) =>
{
    using var reader = new StreamReader(request.Body, Encoding.UTF8);
    var token = await reader.ReadToEndAsync();
    if (string.IsNullOrWhiteSpace(token))
        return Results.Problem("Corpo da requisição vazio ou inválido.", statusCode: StatusCodes.Status400BadRequest);

    var discoveryUrl = config[$"Gateway:ClientDiscovery:{merchantId}"];
    var appXUrl = config["Gateway:AppXUrl"];
    if (string.IsNullOrWhiteSpace(discoveryUrl))
        return Results.Problem($"URL de discovery não configurada para MerchantId '{merchantId}'.", statusCode: StatusCodes.Status400BadRequest);

    await clientKeys.EnsureInitializedAsync(merchantId, discoveryUrl);
    // 1) Decriptar + validar assinatura do CLIENTE
    var jsonPayload = crypto.Unprotect(
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
    var responseToken = crypto.Protect(
        responseJson,
        gatewayKeys.GetJwsPrivate(),          // privada ES384 do gateway
        clientKeys.GetClientEncPublic(merchantId));     // pública ECDH do cliente
    return Results.Text(responseToken, "application/jose");
});

app.Run();

public sealed class GatewayOptions
{
    public string? ClientDiscoveryUrl { get; set; }
    public string? AppXUrl { get; set; }
}