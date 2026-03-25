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
        provider.GetClientSigPublicByKid("m1").Returns(_ => new Dictionary<string, ECDsa>
        {
            ["sig-m1-2026-04"] = ECDsa.Create(ECCurve.NamedCurves.nistP384),
            ["sig-m1-2026-03"] = ECDsa.Create(ECCurve.NamedCurves.nistP384)
        });
        provider.GetClientSigPublicByKid("m2").Returns(_ => new Dictionary<string, ECDsa>
        {
            ["sig-m2-2026-04"] = ECDsa.Create(ECCurve.NamedCurves.nistP384),
            ["sig-m2-2026-03"] = ECDsa.Create(ECCurve.NamedCurves.nistP384)
        });
        provider.GetClientEncPublicByKid(Arg.Any<string>()).Returns(_ =>
        {
            using var e = ECDsa.Create(ECCurve.NamedCurves.nistP384);
            var p = e.ExportParameters(false);
            var k1 = Jose.keys.EccKey.New(p.Q.X!, p.Q.Y!, d: null, usage: CngKeyUsages.KeyAgreement);
            using var e2 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
            var p2 = e2.ExportParameters(false);
            var k2 = Jose.keys.EccKey.New(p2.Q.X!, p2.Q.Y!, d: null, usage: CngKeyUsages.KeyAgreement);
            return new Dictionary<string, CngKey>
            {
                ["enc-fallback-1"] = k1,
                ["enc-fallback-2"] = k2
            };
        });

        var store = Substitute.For<IClientKeyStore>();
        var sut = new KeyInitializer(provider, store, configuration);

        await sut.InitAsync();

        await store.Received(1).MergeMerchantKeysAsync(
            "m1",
            Arg.Is<IReadOnlyDictionary<string, ECDsa>>(d => d.ContainsKey("sig-m1-2026-04") && d.ContainsKey("sig-m1-2026-03")),
            Arg.Any<IReadOnlyDictionary<string, CngKey>>());
        await store.Received(1).MergeMerchantKeysAsync(
            "m2",
            Arg.Is<IReadOnlyDictionary<string, ECDsa>>(d => d.ContainsKey("sig-m2-2026-04") && d.ContainsKey("sig-m2-2026-03")),
            Arg.Any<IReadOnlyDictionary<string, CngKey>>());
    }
}

