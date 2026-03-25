$ErrorActionPreference = 'Stop'

function To-Pem([byte[]]$Bytes, [string]$Label) {
  $b64 = [Convert]::ToBase64String($Bytes)
  $lines = New-Object System.Collections.Generic.List[string]
  for ($i = 0; $i -lt $b64.Length; $i += 64) {
    $len = [Math]::Min(64, $b64.Length - $i)
    $lines.Add($b64.Substring($i, $len))
  }
  "-----BEGIN $Label-----`n$($lines -join "`n")`n-----END $Label-----"
}

function Export-Pkcs8Pem($ecdsa) { To-Pem ($ecdsa.ExportPkcs8PrivateKey()) 'PRIVATE KEY' }
function Export-SpkiPem($ecdsa) { To-Pem ($ecdsa.ExportSubjectPublicKeyInfo()) 'PUBLIC KEY' }

$curve = [System.Security.Cryptography.ECCurve]::NamedCurves.nistP384

$gwSig = [System.Security.Cryptography.ECDsa]::Create($curve)
$gwEnc = [System.Security.Cryptography.ECDsa]::Create($curve)
$mSig  = [System.Security.Cryptography.ECDsa]::Create($curve)
$mEnc  = [System.Security.Cryptography.ECDsa]::Create($curve)

$out = [ordered]@{
  gateway = [ordered]@{
    sigPriv = (Export-Pkcs8Pem $gwSig)
    sigPub  = (Export-SpkiPem $gwSig)
    encPriv = (Export-Pkcs8Pem $gwEnc)
    encPub  = (Export-SpkiPem $gwEnc)
  }
  merchant = [ordered]@{
    sigPriv = (Export-Pkcs8Pem $mSig)
    sigPub  = (Export-SpkiPem $mSig)
    encPriv = (Export-Pkcs8Pem $mEnc)
    encPub  = (Export-SpkiPem $mEnc)
  }
}

$out | ConvertTo-Json -Depth 5

