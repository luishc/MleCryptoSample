using GatewayApi.Infrastructure.Abstractions;
using System.Security.Cryptography;

namespace GatewayApi.Infrastructure
{
    public sealed class ServerOwnKeyStore : IServerOwnKeyStore
    {
        private readonly IKeyMaterialProvider _provider;

        public ServerOwnKeyStore(IKeyMaterialProvider provider)
        {
            _provider = provider ?? throw new ArgumentNullException(nameof(provider));
        }

        public ECDsa GetJwsPrivate() => _provider.GetGatewaySigPrivate();
    public CngKey GetEncPrivate(string kid) => _provider.GetGatewayEncPrivate(kid);
        public string GetCurrentSigKid() => _provider.GetGatewaySigKid();
        public string GetCurrentEncKid() => _provider.GetGatewayEncKid();
    }
}