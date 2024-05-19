# Import the necessary module
Import-Module Microsoft.Graph.Intune

# Function to get Intune managed devices
function Get-IntuneManagedDevices {
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
    
    # Output the devices
    $devices | Format-Table -AutoSize
}

# Get parameters from user
$TenantId = Read-Host "Enter your Tenant ID"
$ClientId = Read-Host "Enter your Client ID"
$ClientSecret = Read-Host "Enter your Client Secret"

# Call the function
Get-IntuneManagedDevices -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
