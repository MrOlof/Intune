# Import the necessary module
Import-Module Microsoft.Graph.Intune

# Function to set device compliance policies
function Set-IntuneDeviceCompliance {
    param (
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientSecret,
        
        [Parameter(Mandatory = $true)]
        [string]$PolicyId,
        
        [Parameter(Mandatory = $true)]
        [string]$Setting,
        
        [Parameter(Mandatory = $true)]
        [string]$Value
    )
    
    # Connect to Microsoft Graph
    $token = (New-IntuneAuthToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret).access_token
    Connect-MSGraph -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
    
    # Set compliance policy settings
    Set-IntuneDeviceCompliancePolicySetting -PolicyId $PolicyId -Setting $Setting -Value $Value
    
    Write-Output "Compliance policy settings updated for policy ID $PolicyId."
}

# Get parameters from user
$TenantId = Read-Host "Enter your Tenant ID"
$ClientId = Read-Host "Enter your Client ID"
$ClientSecret = Read-Host "Enter your Client Secret"
$PolicyId = Read-Host "Enter the policy ID"
$Setting = Read-Host "Enter the setting name"
$Value = Read-Host "Enter the setting value"

# Call the function
Set-IntuneDeviceCompliance -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -PolicyId $PolicyId -Setting $Setting -Value $Value
