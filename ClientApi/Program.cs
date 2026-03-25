using ClientApi;
using ClientApi.Infrastructure;
using ClientApi.Infrastructure.Abstractions;
using ClientApi.Infrastructure.Helpers;
using ClientApi.Models;
using TokenCredential = Azure.Core.TokenCredential;
using Azure.Identity;
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

builder.Services.Configure<ClientKeyVaultOptions>(builder.Configuration.GetSection("Client:KeyVault"));
builder.Services.Configure<LocalClientKeysOptions>(builder.Configuration.GetSection("Client:LocalKeys"));

builder.Services.AddSingleton<TokenCredential>(_ => new DefaultAzureCredential());
builder.Services.AddSingleton<IClientKeyMaterialProvider>(sp =>
{
    var mode = builder.Configuration["Client:KeyManagement:Mode"]?.Trim();
    if (string.Equals(mode, "Local", StringComparison.OrdinalIgnoreCase))
        return new LocalAppsettingsClientKeyMaterialProvider(sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<LocalClientKeysOptions>>());
    return new KeyVaultClientKeyMaterialProvider(
        sp.GetRequiredService<TokenCredential>(),
        sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<ClientKeyVaultOptions>>(),
        builder.Configuration);
});

var app = builder.Build();

// Primeira execução: inicialização de chaves no startup; se falhar, a aplicação não sobe.
using (var scope = app.Services.CreateScope())
{
    var provider = scope.ServiceProvider.GetRequiredService<IClientKeyMaterialProvider>();
    await provider.InitializeAsync();
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.MapPost("/client/send", async (
    [FromBody] object payload,
    IClientOwnKeyStore clientKeys,
    IServerKeyStore serverKeys,
    ICryptoService crypto,
    IHttpClientFactory httpClientFactory,
    IConfiguration config) =>
{
    var jsonPayload = JsonSerializer.Serialize(payload);
    var processUrl = config["Client:GatewayProcessUrl"];
    var merchantId = config["Client:MerchantId"];

    var clientSigKid = clientKeys.GetCurrentSigKid();
    var gatewayEncKid = serverKeys.GetCurrentEncKid();
    var jweToken = crypto.Protect(
        jsonPayload,
        clientKeys.GetJwsPrivate(),
        serverKeys.GetServerEncPublic(gatewayEncKid),
        clientSigKid,
        gatewayEncKid);
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
    var clientEncKid = JwtHeaderHelper.GetKidFromToken(responseToken)
                       ?? throw new InvalidOperationException("Token JWE de resposta não contém 'kid' no header.");
    var jsonResponse = crypto.Unprotect(
        responseToken,
        clientKeys.GetEncPrivate(clientEncKid),
        kid => serverKeys.GetServerJwsPublic(kid));
    return Results.Text(jsonResponse, "application/json");
});

app.Run();