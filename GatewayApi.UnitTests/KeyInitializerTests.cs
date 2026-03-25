using GatewayApi.Infrastructure;
using GatewayApi.Infrastructure.Abstractions;
using GatewayApi.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using NSubstitute;
using System.Security.Cryptography;
using Xunit;

namespace GatewayApi.UnitTests;

public sealed class KeyInitializerTests
{
    [Fact]
    public async Task InitAsync_Throws_WhenNoMerchantsConfigured()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>()).Build();
        var provider = Substitute.For<IKeyMaterialProvider>();
        var store = Substitute.For<IClientKeyStore>();
        var sut = new KeyInitializer(provider, store, configuration);

        await Assert.ThrowsAsync<InvalidOperationException>(() => sut.InitAsync());
    }

    [Fact]
    public async Task InitAsync_Throws_WhenSourceNotKeyVault()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Gateway:Merchants:m1:Source"] = "Discovery"
            })
            .Build();
        var provider = Substitute.For<IKeyMaterialProvider>();
        var store = Substitute.For<IClientKeyStore>();
        var sut = new KeyInitializer(provider, store, configuration);

        await Assert.ThrowsAsync<InvalidOperationException>(() => sut.InitAsync());
    }

    [Fact]
    public async Task InitAsync_MergesKeysForEachMerchant()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Gateway:Merchants:m1:Source"] = "KeyVault",
                ["Gateway:Merchants:m2:Source"] = "KeyVault"
            })
            .Build();

        var provider = Substitute.For<IKeyMaterialProvider>();
        provider.GetClientSigKid("m1").Returns("sig-m1-2026-03");
        provider.GetClientEncKid("m1").Returns("enc-m1-2026-03");
        provider.GetClientSigKid("m2").Returns("sig-m2-2026-03");
        provider.GetClientEncKid("m2").Returns("enc-m2-2026-03");
        provider.GetClientSigPublic(Arg.Any<string>()).Returns(_ => ECDsa.Create(ECCurve.NamedCurves.nistP384));
        provider.GetClientEncPublic(Arg.Any<string>()).Returns(_ =>
        {
            using var e = ECDsa.Create(ECCurve.NamedCurves.nistP384);
            var p = e.ExportParameters(false);
            return Jose.keys.EccKey.New(p.Q.X!, p.Q.Y!, d: null, usage: CngKeyUsages.KeyAgreement);
        });

        var store = Substitute.For<IClientKeyStore>();
        var sut = new KeyInitializer(provider, store, configuration);

        await sut.InitAsync();

        await store.Received(1).MergeMerchantKeysAsync(
            "m1",
            Arg.Any<IReadOnlyDictionary<string, ECDsa>>(),
            Arg.Any<IReadOnlyDictionary<string, CngKey>>());
        await store.Received(1).MergeMerchantKeysAsync(
            "m2",
            Arg.Any<IReadOnlyDictionary<string, ECDsa>>(),
            Arg.Any<IReadOnlyDictionary<string, CngKey>>());
    }
}

