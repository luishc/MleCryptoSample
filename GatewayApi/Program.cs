using GatewayApi.Endpoints;
using GatewayApi.Infrastructure.Abstractions;
using GatewayApi.Infrastructure.Extensions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddHttpClient();

builder.Services.ConfigureModules(builder.Configuration);

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var discoverService = scope.ServiceProvider.GetRequiredService<IDiscoveryClientsPublicKeys>();
    await discoverService.InitAsync();
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.MapDiscoveryEndpoints();
app.MapSecureEndpoints();

app.Run();