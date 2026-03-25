using System.Security.Cryptography;

namespace ClientApi.Infrastructure.Abstractions;

public interface IServerKeyStore
{
    ECDsa GetServerJwsPublic(string kid);
    CngKey GetServerEncPublic(string kid);
    string GetCurrentSigKid();
    string GetCurrentEncKid();
}

