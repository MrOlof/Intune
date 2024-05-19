# Import the necessary module
Import-Module Microsoft.Graph.Intune

# Function to export Intune policies
function Export-IntunePolicies {
    param (
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientSecret,
        
        [Parameter(Mandatory = $true)]
        [string]$ExportPath
    )
    
    # Connect to Microsoft Graph
    $token = (New-IntuneAuthToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret).access_token
    Connect-MSGraph -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
    
    # Get and export configuration policies
    $configPolicies = Get-IntuneDeviceConfigurationPolicy
    $configPolicies | Export-Csv -Path "$ExportPath\ConfigPolicies.csv" -NoTypeInformation
    
    # Get and export compliance policies
    $compliancePolicies = Get-IntuneDeviceCompliancePolicy
    $compliancePolicies | Export-Csv -Path "$ExportPath\CompliancePolicies.csv" -NoTypeInformation
    
    Write-Output "Policies exported to $ExportPath"
}

# Get parameters from user
$TenantId = Read-Host "Enter your Tenant ID"
$ClientId = Read-Host "Enter your Client ID"
$ClientSecret = Read-Host "Enter your Client Secret"
$ExportPath = Read-Host "Enter the export path"

# Call the function
Export-IntunePolicies -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -ExportPath $ExportPath
