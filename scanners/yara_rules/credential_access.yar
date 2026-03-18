rule credential_access
{
  strings:
    $aws = ".aws/credentials" ascii nocase
    $ssh = "id_rsa" ascii nocase
    $gcloud = ".config/gcloud" ascii nocase
    $npm = ".npmrc" ascii nocase
  condition:
    any of them
}
