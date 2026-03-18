rule encoded_blob
{
  strings:
    $base64 = /[A-Za-z0-9+\/]{220,}={0,2}/
    $b64func = "base64.b64decode" ascii nocase
  condition:
    $base64 or $b64func
}
