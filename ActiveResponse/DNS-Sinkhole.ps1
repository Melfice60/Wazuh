# Script de sinkhole de domaine a destination de l'agent Wazuh
# Ecrit les domaines detectés comme malveillants dans etc\hosts avec une resolution sur le localhost
# version PS1, à integrer dans la regle MISP de detection de domaine malveillant avec detection du label Windows
# 1.0

#Lecture de l'alerte fournie par Wazuh
$INPUT_JSON = Read-host
$INPUT_ARRAY = $INPUT_JSON | ConvertFrom-Json
$INPUT_ARRAY = $INPUT_ARRAY | ConvertFrom-Json
$ErrorActionPreference = "SilentlyContinue"

#Extraction de l'url cible à partir de l'alerte MISP
$malicious_domain = $INPUT_ARRAY."parameters"."alert"."data"."misp"."value"

#sinkhole local
Add-Content -Path $env:windir\System32\drivers\etc\hosts -Value "`n127.0.0.1 `t$malicious_domain" -Force
