using System.Security.Cryptography;
using GatewayApi.Infrastructure;
using GatewayApi.Infrastructure.Abstractions;
using Xunit;

namespace GatewayApi.UnitTests;

public sealed class ClientKeyStoreTests
{
    [Theory]
    [InlineData("sig-abc", "enc-abc")]
    [InlineData("sig-prefix-rest", "enc-prefix-rest")]
    public void DeriveEncKidFromSigKid_ReplacesSigPrefix(string sigKid, string expectedEncKid)
    {
        var store = new ClientKeyStore();

        var encKid = store.DeriveEncKidFromSigKid(sigKid);

        Assert.Equal(expectedEncKid, encKid);
    }

    [Fact]
    public void DeriveEncKidFromSigKid_WhenNoSigPrefix_PrefixesEnc()
    {
        var store = new ClientKeyStore();

        Assert.Equal("enc-legacy", store.DeriveEncKidFromSigKid("legacy"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void DeriveEncKidFromSigKid_Throws_ForNullOrEmpty(string? sigKid)
    {
        var store = new ClientKeyStore();

        Assert.Throws<ArgumentException>(() => store.DeriveEncKidFromSigKid(sigKid!));
    }

    [Fact]
    public void MergeMerchantKeysAsync_Throws_WhenMerchantIdMissing()
    {
        IClientKeyStore store = new ClientKeyStore();

        Assert.Throws<ArgumentException>(() =>
            store.MergeMerchantKeysAsync(" ", new Dictionary<string, ECDsa>(), new Dictionary<string, CngKey>())
                .GetAwaiter().GetResult());
    }

    [Fact]
    public void GetClientJwsPublic_Throws_WhenKidUnknown()
    {
        var store = new ClientKeyStore();

        Assert.Throws<InvalidOperationException>(() => store.GetClientJwsPublic("m1", "missing"));
    }

    [Fact]
    public void GetClientEncPublic_Throws_WhenKidUnknown()
    {
        var store = new ClientKeyStore();

        Assert.Throws<InvalidOperationException>(() => store.GetClientEncPublic("m1", "missing"));
    }

    [Fact]
    public async Task MergeMerchantKeysAsync_AllowsCurrentAndPreviousKids()
    {
        var store = new ClientKeyStore();
        using var sigCurrent = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        using var sigPrevious = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        using var encCurrentSeed = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        using var encPreviousSeed = ECDsa.Create(ECCurve.NamedCurves.nistP384);

        var pCur = encCurrentSeed.ExportParameters(false);
        var pPrev = encPreviousSeed.ExportParameters(false);
        var encCurrent = Jose.keys.EccKey.New(pCur.Q.X!, pCur.Q.Y!, d: null, usage: CngKeyUsages.KeyAgreement);
        var encPrevious = Jose.keys.EccKey.New(pPrev.Q.X!, pPrev.Q.Y!, d: null, usage: CngKeyUsages.KeyAgreement);

        await store.MergeMerchantKeysAsync(
            "m1",
            new Dictionary<string, ECDsa>
            {
                ["sig-m1-2026-04"] = sigCurrent,
                ["sig-m1-2026-03"] = sigPrevious
            },
            new Dictionary<string, CngKey>
            {
                ["enc-m1-2026-04"] = encCurrent,
                ["enc-m1-2026-03"] = encPrevious
            });

        Assert.NotNull(store.GetClientJwsPublic("m1", "sig-m1-2026-04"));
        Assert.NotNull(store.GetClientJwsPublic("m1", "sig-m1-2026-03"));
        Assert.NotNull(store.GetClientEncPublic("m1", "enc-m1-2026-04"));
        Assert.NotNull(store.GetClientEncPublic("m1", "enc-m1-2026-03"));
    }
}
