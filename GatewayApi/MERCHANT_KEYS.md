# Chaves públicas do cliente por MerchantId

O gateway carrega as chaves públicas de cada loja no startup (e no refresh diário) usando uma destas fontes:

## Configuração global do Key Vault

Quando algum merchant usa `Source: KeyVault`, defina **uma única vez**:

```json
"Gateway": {
  "KeyVault": {
    "Uri": "https://meu-vault.vault.azure.net/",
    "CertificateVersionSuffix": "2026-03"
  }
}
```

Nomes dos certificados no vault (por merchant):

- `sig-{MerchantId}-{CertificateVersionSuffix}`  
- `enc-{MerchantId}-{CertificateVersionSuffix}`  

Exemplo com `MerchantId` = `fe9af6ea-40dd-4be6-b38a-9d2a38f1d6d9` e sufixo `2026-03`:

- `sig-fe9af6ea-40dd-4be6-b38a-9d2a38f1d6d9-2026-03`
- `enc-fe9af6ea-40dd-4be6-b38a-9d2a38f1d6d9-2026-03`

Os **mesmos** valores são usados como `kid` nos headers JWS/JWE. O cliente deve assinar/criptografar com esses `kid` ao falar com o gateway para esse merchant.

## Seção `Gateway:Merchants`

### Discovery (JWKS)

```json
"Merchants": {
  "fe9af6ea-40dd-4be6-b38a-9d2a38f1d6d9": {
    "Source": "Discovery",
    "DiscoveryUrl": "https://cliente/.well-known/jwks.json"
  }
}
```

### Key Vault

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
