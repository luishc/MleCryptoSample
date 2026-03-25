#!/usr/bin/env bash
set -euo pipefail

# Generates EC P-384 certs (sig/enc) for:
# - a merchant (MerchantId)
# - the gateway (GatewayId)
#
# Output: PFX files ready to import into Azure Key Vault Certificates.
#
# Usage:
#   ./scripts/generate-kv-certs.sh \
#     --merchant-id "fe9af6ea-40dd-4be6-b38a-9d2a38f1d6d9" \
#     --suffix "2026-03" \
#     --gateway-id "gateway" \
#     --out "./out-kv"
#
# Then import:
#   az keyvault certificate import --vault-name "<vault>" --name "sig-<id>-<suffix>" --file "./out-kv/sig-<id>-<suffix>.pfx" --password "<pfxpass>"

merchant_id=""
suffix=""
gateway_id="gateway"
out_dir="./out-kv"
pfx_pass=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --merchant-id) merchant_id="$2"; shift 2;;
    --suffix) suffix="$2"; shift 2;;
    --gateway-id) gateway_id="$2"; shift 2;;
    --out) out_dir="$2"; shift 2;;
    --pfx-pass) pfx_pass="$2"; shift 2;;
    -h|--help)
      sed -n '1,60p' "$0"; exit 0;;
    *) echo "Unknown arg: $1" >&2; exit 2;;
  esac
done

if [[ -z "$merchant_id" || -z "$suffix" ]]; then
  echo "Missing required args: --merchant-id and --suffix" >&2
  exit 2
fi

if [[ -z "$pfx_pass" ]]; then
  echo "Enter PFX password (will not echo):" >&2
  read -r -s pfx_pass
  echo >&2
fi

mkdir -p "$out_dir"

gen_pair () {
  local name="$1"   # e.g. sig-fe9a...-2026-03
  local cn="$2"     # cert subject CN

  local key_pem="$out_dir/$name.key.pem"
  local crt_pem="$out_dir/$name.crt.pem"
  local pfx="$out_dir/$name.pfx"
  local pub_pem="$out_dir/$name.pub.pem"

  # EC key (P-384) in PKCS#8
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$key_pem" >/dev/null 2>&1

  # Self-signed certificate (10y)
  openssl req -new -x509 -key "$key_pem" -out "$crt_pem" -days 3650 -subj "/CN=$cn" >/dev/null 2>&1

  # Public key (optional convenience)
  openssl pkey -in "$key_pem" -pubout -out "$pub_pem" >/dev/null 2>&1

  # PFX (for Key Vault certificate import)
  openssl pkcs12 -export -out "$pfx" -inkey "$key_pem" -in "$crt_pem" -passout "pass:$pfx_pass" >/dev/null 2>&1

  echo "Generated: $pfx"
}

gw_sig="sig-${gateway_id}-${suffix}"
gw_enc="enc-${gateway_id}-${suffix}"
m_sig="sig-${merchant_id}-${suffix}"
m_enc="enc-${merchant_id}-${suffix}"

echo "== Gateway certs ==" >&2
gen_pair "$gw_sig" "$gw_sig"
gen_pair "$gw_enc" "$gw_enc"

echo "== Merchant certs ==" >&2
gen_pair "$m_sig" "$m_sig"
gen_pair "$m_enc" "$m_enc"

cat <<EOF

Done.

Files in: $out_dir

Import commands (Azure CLI):
  az keyvault certificate import --vault-name "<vaultName>" --name "$gw_sig" --file "$out_dir/$gw_sig.pfx" --password "<pfxpass>"
  az keyvault certificate import --vault-name "<vaultName>" --name "$gw_enc" --file "$out_dir/$gw_enc.pfx" --password "<pfxpass>"
  az keyvault certificate import --vault-name "<vaultName>" --name "$m_sig"  --file "$out_dir/$m_sig.pfx"  --password "<pfxpass>"
  az keyvault certificate import --vault-name "<vaultName>" --name "$m_enc"  --file "$out_dir/$m_enc.pfx"  --password "<pfxpass>"

Notes:
  - This generates self-signed certs. In produção, se você precisar de CA/chain, substitua o passo de 'req -x509'.
  - Key Vault 'certificate import' cria o secret associado (PFX base64) que o código usa para ler a private key.
EOF

