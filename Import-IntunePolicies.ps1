# Import the necessary module
Import-Module Microsoft.Graph.Intune

# Function to import Intune policies
function Import-IntunePolicies {
    param (
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientSecret,
        
        [Parameter(Mandatory = $true)]
        [string]$ImportPath
    )
    
    # Connect to Microsoft Graph
    $token = (New-IntuneAuthToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret).access_token
    Connect-MSGraph -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
    
    # Import configuration policies
    $configPolicies = Import-Csv -Path "$ImportPath\ConfigPolicies.csv"
    foreach ($policy in $configPolicies) {
        New-IntuneDeviceConfigurationPolicy -DisplayName $policy.DisplayName -Description $policy.Description -OmaUriSettings $policy.OmaUriSettings
    }
    
    # Import compliance policies
    $compliancePolicies = Import-Csv -Path "$ImportPath\CompliancePolicies.csv"
    foreach ($policy in $compliancePolicies) {
        New-IntuneDeviceCompliancePolicy -DisplayName $policy.DisplayName -Description $policy.Description -ScheduledActionsForRule $policy.ScheduledActionsForRule
    }
    
    Write-Output "Policies imported from $ImportPath"
}

# Get parameters from user
$TenantId = Read-Host "Enter your Tenant ID"
$ClientId = Read-Host "Enter your Client ID"
$ClientSecret = Read-Host "Enter your Client Secret"
$ImportPath = Read-Host "Enter the import path"

# Call the function
Import-IntunePolicies -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -ImportPath $ImportPath
