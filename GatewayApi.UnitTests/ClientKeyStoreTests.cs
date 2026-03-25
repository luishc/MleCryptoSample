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
}
