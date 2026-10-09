# Regenerates the n8n workflows, imports them into the project-local n8n and publishes them. Stop n8n first, start it again afterwards.
$p = Split-Path $PSScriptRoot -Parent
$env:N8N_USER_FOLDER = "$p\n8n\data"
$env:N8N_DIAGNOSTICS_ENABLED = "false"
$env:N8N_PERSONALIZATION_ENABLED = "false"
& "$p\.venv\Scripts\python.exe" "$p\scripts\build_n8n_workflows.py"
$cli = "$p\n8n\node_modules\n8n\bin\n8n"
node $cli import:workflow --separate --input="$p\workflows"
foreach ($id in "socAgent01", "socOrch01", "socClose01", "socErr01") { node $cli publish:workflow --id=$id }
node $cli list:workflow --active=true
