using ClientApi;
using Microsoft.AspNetCore.Mvc;
using System.Text;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddHttpClient();

builder.Services.AddSingleton<IClientOwnKeyStore, ClientOwnKeyStore>();
builder.Services.AddSingleton<IServerKeyStore, ServerKeyStore>();
builder.Services.AddSingleton<ICryptoService, CryptoService>();
builder.Services.AddHostedService<GatewayJwksRefreshService>();

builder.Services.Configure<ClientOptions>(builder.Configuration.GetSection("Client"));

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.MapGet("/discovery/keys", ([FromServices] IClientOwnKeyStore keys) =>
{
    var dto = keys.GetDiscoveryKeys();
    return Results.Json(dto);
});

app.MapGet("/.well-known/jwks.json", ([FromServices] IClientOwnKeyStore keys) =>
{
    var jwks = new JwkSet
    {
        Keys = keys.GetJwkKeys()
    };

    return Results.Json(jwks);
});

app.MapGet("/.well-known/jose-configuration", (HttpRequest request) =>
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
});

app.MapPost("/client/send", async (
    [FromBody] object payload,
    IClientOwnKeyStore clientKeys,
    IServerKeyStore serverKeys,
    ICryptoService crypto,
    IHttpClientFactory httpClientFactory,
    IConfiguration config) =>
{
    var jsonPayload = JsonSerializer.Serialize(payload);
    var discoveryUrl = config["Client:GatewayDiscoveryUrl"];
    var processUrl = config["Client:GatewayProcessUrl"];
    var merchantId = config["Client:MerchantId"];
    await serverKeys.EnsureInitializedAsync(discoveryUrl!);
    var jweToken = crypto.Protect(
        jsonPayload,
        clientKeys.GetJwsPrivate(),          // assina com chave privada do cliente (ES384)
        serverKeys.GetServerEncPublic());    // criptografa para a chave ECDH pública do gateway
    var http = httpClientFactory.CreateClient();
    var request = new HttpRequestMessage(HttpMethod.Post, processUrl)
    {
        Content = new StringContent(jweToken, Encoding.UTF8, "application/jose")
    };
    if (!string.IsNullOrWhiteSpace(merchantId))
    {
        request.Headers.Add("MerchantId", merchantId);
    }
    var resp = await http.SendAsync(request);
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