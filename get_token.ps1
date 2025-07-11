# Azure app registration details
$clientId = $env:AZURE_CLIENT_ID
$clientSecret = $env:AZURE_CLIENT_SECRET
$tenantId = $env:AZURE_TENANT_ID

# Validate required environment variables
if (-not $clientId -or -not $clientSecret -or -not $tenantId) {
    Write-Error "Required environment variables not set: AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID"
    exit 1
}

try {
    # Get access token
    $tokenBody = @{
        grant_type = "client_credentials"
        client_id = $clientId
        client_secret = $clientSecret
        scope = "https://graph.microsoft.com/.default"
    }

    Write-Host "Getting access token..." -ForegroundColor Yellow
    $tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Method POST -Body $tokenBody
    $headers = @{ Authorization = "Bearer $($tokenResponse.access_token)" }

    Write-Host "Access token retrieved successfully" -ForegroundColor Green
    # Store token securely instead of printing
    $env:AZURE_ACCESS_TOKEN = $tokenResponse.access_token
} catch {
    Write-Error "Failed to retrieve access token: $($_.Exception.Message)"
    exit 1
}