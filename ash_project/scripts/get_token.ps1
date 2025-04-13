# scripts/get_token.ps1
$headers = @{"Content-Type"="application/json"}
$body = @{
    username = "postgres"
    password = "AshLiam2025"
} | ConvertTo-Json

try {
    $response = Invoke-WebRequest -Uri "http://127.0.0.1:5000/api/auth/login" `
        -Method POST `
        -Headers $headers `
        -Body $body `
        -ErrorAction Stop
    
    $token = ($response.Content | ConvertFrom-Json).access_token
    Write-Host "SUCCESS! Token: $token" -ForegroundColor Green
    $token | Set-Clipboard
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
}