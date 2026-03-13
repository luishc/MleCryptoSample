using ClientApi;
using Microsoft.AspNetCore.Mvc;
using System.Text;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddHttpClient();

builder.Services.AddSingleton<ClientOwnKeyStore>();
builder.Services.AddSingleton<ServerKeyStore>();
builder.Services.AddSingleton<CryptoService>();

builder.Services.Configure<ClientOptions>(builder.Configuration.GetSection("Client"));

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.MapGet("/discovery/keys", ([FromServices] ClientOwnKeyStore keys) =>
{
    var dto = keys.GetDiscoveryKeys();
    return Results.Json(dto);
});

app.MapPost("/client/send", async (
    [FromBody] object payload,
    ClientOwnKeyStore clientKeys,
    ServerKeyStore serverKeys,
    CryptoService crypto,
    IHttpClientFactory httpClientFactory,
    IConfiguration config) =>
{
    var jsonPayload = JsonSerializer.Serialize(payload);
    var discoveryUrl = config["Client:GatewayDiscoveryUrl"];
    var processUrl = config["Client:GatewayProcessUrl"];
    await serverKeys.EnsureInitializedAsync(discoveryUrl!);
    var jweToken = crypto.Protect(
        jsonPayload,
        clientKeys.GetJwsPrivate(),          // assina com chave privada do cliente (ES384)
        serverKeys.GetServerEncPublic());    // criptografa para a chave ECDH pública do gateway
    var http = httpClientFactory.CreateClient();
    var content = new StringContent(jweToken, Encoding.UTF8, "application/jose");
    var resp = await http.PostAsync(processUrl, content);
    if (!resp.IsSuccessStatusCode)
        return Results.Problem($"Falha ao chamar gateway. Status {(int)resp.StatusCode}");
    var responseToken = await resp.Content.ReadAsStringAsync();
    // Inverso: gateway → cliente
    var jsonResponse = crypto.Unprotect(
        responseToken,
        clientKeys.GetEncPrivate(),           // decripta com privada ECDH do cliente
        serverKeys.GetServerJwsPublic());     // valida assinatura ES384 do gateway
    return Results.Text(jsonResponse, "application/json");
});

app.Run();

public sealed class ClientOptions
{
    public string? GatewayDiscoveryUrl { get; set; }
    public string? GatewayProcessUrl { get; set; }
}