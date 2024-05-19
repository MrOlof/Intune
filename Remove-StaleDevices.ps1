# Import the necessary module
Import-Module Microsoft.Graph.Intune

# Function to remove stale devices
function Remove-StaleDevices {
    param (
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientSecret
    )
    
    # Connect to Microsoft Graph
    $token = (New-IntuneAuthToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret).access_token
    Connect-MSGraph -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
    
    # Get managed devices
    $devices = Get-IntuneManagedDevice
    
    # Define stale period (e.g., 90 days)
    $stalePeriod = (Get-Date).AddDays(-90)
    
    # Identify and remove stale devices
    $staleDevices = $devices | Where-Object { $_.LastSyncDateTime -lt $stalePeriod }
    foreach ($device in $staleDevices) {
        Remove-IntuneManagedDevice -Id $device.Id
        Write-Output "Removed stale device: $($device.DeviceName)"
    }
    
    Write-Output "Stale devices removal completed."
}

# Get parameters from user
$TenantId = Read-Host "Enter your Tenant ID"
$ClientId = Read-Host "Enter your Client ID"
$ClientSecret = Read-Host "Enter your Client Secret"

# Call the function
Remove-StaleDevices -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
