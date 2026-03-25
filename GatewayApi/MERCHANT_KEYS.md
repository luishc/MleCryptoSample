# Chaves por MerchantId (KV-only)

Os endpoints de discovery/JWKS foram descontinuados. **GatewayApi** e **ClientApi** passam a trabalhar somente com Azure Key Vault (produção) ou chaves locais no `appsettings` (desenvolvimento).

## GatewayApi: Key Vault (produção)

Defina **uma única vez**:

```json
"Gateway": {
  "KeyVault": {
    "Uri": "https://meu-vault.vault.azure.net/",
    "CertificateVersionSuffix": "2026-03",
    "GatewayId": "gateway"
  }
}
```

### Certificados (por merchant / client keys)

- `sig-{MerchantId}-{CertificateVersionSuffix}`  
- `enc-{MerchantId}-{CertificateVersionSuffix}`  

Exemplo com `MerchantId` = `fe9af6ea-40dd-4be6-b38a-9d2a38f1d6d9` e sufixo `2026-03`:

- `sig-fe9af6ea-40dd-4be6-b38a-9d2a38f1d6d9-2026-03`
- `enc-fe9af6ea-40dd-4be6-b38a-9d2a38f1d6d9-2026-03`

Os **mesmos** valores são usados como `kid` nos headers JWS/JWE. O cliente deve assinar/criptografar com esses `kid` ao falar com o gateway para esse merchant.

### Certificados do próprio gateway

O **gateway** também precisa de seus próprios certificados **com chave privada** no KV:

```json
"sig-{GatewayId}-{CertificateVersionSuffix}"
"enc-{GatewayId}-{CertificateVersionSuffix}"
```

## GatewayApi: Seção `Gateway:Merchants`

Apenas o `Source` (além do `MerchantId` na chave do JSON):

```json
"Merchants": {
  "fe9af6ea-40dd-4be6-b38a-9d2a38f1d6d9": {
    "Source": "KeyVault"
  }
}
```

É obrigatório existir **pelo menos um** merchant em `Gateway:Merchants`; sem essa seção (ou sem filhos) o gateway não inicia.

Autenticação no Azure: `DefaultAzureCredential`.

## Modo local (desenvolvimento)

### GatewayApi

Seleção do modo:

```json
"Gateway": {
  "KeyManagement": { "Mode": "Local" },
  "LocalKeys": {
    "Gateway": {
      "SigKid": "sig-gateway-2026-03",
      "EncKid": "enc-gateway-2026-03",
      "SigPrivateKeyPem": "-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----",
      "EncPrivateKeyPem": "-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----"
    },
    "Merchants": {
      "fe9af6ea-40dd-4be6-b38a-9d2a38f1d6d9": {
        "SigKid": "sig-fe9af6ea-40dd-4be6-b38a-9d2a38f1d6d9-2026-03",
        "EncKid": "enc-fe9af6ea-40dd-4be6-b38a-9d2a38f1d6d9-2026-03",
        "SigPublicKeyPem": "-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----",
        "EncPublicKeyPem": "-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----"
      }
    }
  }
}
```

### ClientApi

```json
"Client": {
  "KeyManagement": { "Mode": "Local" },
  "MerchantId": "fe9af6ea-40dd-4be6-b38a-9d2a38f1d6d9",
  "LocalKeys": {
    "Client": {
      "SigKid": "sig-fe9af6ea-40dd-4be6-b38a-9d2a38f1d6d9-2026-03",
      "EncKid": "enc-fe9af6ea-40dd-4be6-b38a-9d2a38f1d6d9-2026-03",
      "SigPrivateKeyPem": "-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----",
      "EncPrivateKeyPem": "-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----"
    },
    "Gateway": {
      "SigKid": "sig-gateway-2026-03",
      "EncKid": "enc-gateway-2026-03",
      "SigPublicKeyPem": "-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----",
      "EncPublicKeyPem": "-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----"
    }
  }
}
```
