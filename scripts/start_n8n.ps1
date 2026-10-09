# Starts the project-local n8n (data kept inside the project). UI: http://localhost:5678
$p = Split-Path $PSScriptRoot -Parent
$env:N8N_USER_FOLDER = "$p\n8n\data"
$env:N8N_PORT = "5678"
$env:N8N_DIAGNOSTICS_ENABLED = "false"
$env:N8N_PERSONALIZATION_ENABLED = "false"
& "$p\n8n\node_modules\.bin\n8n.cmd" start
