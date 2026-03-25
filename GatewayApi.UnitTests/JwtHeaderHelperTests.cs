using System.Text;
using GatewayApi.Infrastructure.Helpers;
using Xunit;

namespace GatewayApi.UnitTests;

public sealed class JwtHeaderHelperTests
{
    [Fact]
    public void GetKidFromToken_ReturnsKid_WhenHeaderContainsKid()
    {
        var headerJson = """{"alg":"ES384","kid":"sig-merchant-2026-03"}""";
        var token = EncodeJwtPart(headerJson) + ".eyJzdWIiOiIxIn0.signature";

        var kid = JwtHeaderHelper.GetKidFromToken(token);

        Assert.Equal("sig-merchant-2026-03", kid);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void GetKidFromToken_ReturnsNull_ForNullOrWhiteSpace(string? token)
    {
        Assert.Null(JwtHeaderHelper.GetKidFromToken(token!));
    }

    [Fact]
    public void GetKidFromToken_ReturnsNull_WhenSinglePart()
    {
        Assert.Null(JwtHeaderHelper.GetKidFromToken("onlyonepart"));
    }

    [Fact]
    public void GetKidFromToken_ReturnsNull_WhenHeaderJsonInvalid()
    {
        var token = EncodeJwtPart("not-json") + ".x.y";

        Assert.Null(JwtHeaderHelper.GetKidFromToken(token));
    }

    [Fact]
    public void GetKidFromToken_ReturnsNull_WhenKidMissing()
    {
        var token = EncodeJwtPart("""{"alg":"ES384"}""") + ".x.y";

        Assert.Null(JwtHeaderHelper.GetKidFromToken(token));
    }

    private static string EncodeJwtPart(string utf8Json)
    {
        var bytes = Encoding.UTF8.GetBytes(utf8Json);
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
