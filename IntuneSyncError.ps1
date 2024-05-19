

########
### Version 0.17 | This tool will check for missing Intune certificates, if the Certificate is in the wrong 
certificate store, and if the certificate has been expired
#######

# downloading gif if enrollment succeeds #

$path = "C:\temp"
if (!(Test-Path $path))
{
New-Item -Path $path -ItemType Directory -Force -Confirm:$false
}
$img = Invoke-WebRequest -Uri "https://call4cloud.nl/wp-content/uploads/2022/09/487ba55465e8cf5ff78ea5bf8cf06e4a.gif" 
-OutFile "$path\membeer.gif" -ErrorAction:Stop

Add-Type -AssemblyName System.Windows.Forms
$Form = New-Object System.Windows.Forms.Form
$Form.AutoSize = $true
$Form.StartPosition = "CenterScreen"

$Form.Text = "Membeer Player"
$Label = New-Object System.Windows.Forms.Label
$Label.Location = New-Object System.Drawing.Size(0,0)
$Label.AutoSize = $true
$Label.Font = New-Object System.Drawing.Font ("Comic Sans MS",20, [System.Drawing.Fontstyle]::Bold)
$Label.Text = "MDE Successful!"
$Form.Controls.Add($Label)

$gifBox = New-Object Windows.Forms.picturebox
$gifLink= (Get-Item -Path 'C:\temp\membeer.gif')
$img = [System.Drawing.Image]::fromfile($gifLink)
$gifBox.AutoSize = $true
$gifBox.Image = $img
$Form.Controls.Add($gifbox)


#################################
#defining some functions first###
###################################

function fix-wrongstore { 
                $title    = 'Fixing missing Certificate in the System Store'
                $question = 'Are you sure you want to proceed?'
                $choices  = '&Yes', '&No'
                $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
                
                if ($decision -eq 0) 
                {        
                        $progressPreference = 'silentlyContinue'
                            write-host "Exporting and Importing the Intune certificate to the proper Certificate 
Store" -foregroundcolor yellow
                            Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/PSTools.zip' -OutFile 
'pstools.zip'
                        Expand-Archive -Path 'pstools.zip' -DestinationPath "$env:TEMP\pstools" -force
                        #Move-Item -Path "$env:TEMP\pstools\psexec.exe" -force
                        reg.exe ADD HKCU\Software\Sysinternals /v EulaAccepted /t REG_DWORD /d 1 /f | out-null
                        Start-Process -windowstyle hidden -FilePath "$env:TEMP\pstools\psexec.exe" -ArgumentList '-s 
cmd /c "powershell.exe -ExecutionPolicy Bypass -encodedcommand JABjAGUAcgB0AGkAZgBpAGMAYQB0AGUAIAA9ACAARwBlAHQALQBDAGgA
aQBsAGQASQB0AGUAbQAgAC0AUABhAHQAaAAgAEMAZQByAHQAOgBcAEMAdQByAHIAZQBuAHQAdQBzAGUAcgBcAE0AeQBcAAoAJABwAGEAcwBzAHcAbwByAGQ
APQAgACIAcwBlAGMAcgBlAHQAIgAgAHwAIABDAG8AbgB2AGUAcgB0AFQAbwAtAFMAZQBjAHUAcgBlAFMAdAByAGkAbgBnACAALQBBAHMAUABsAGEAaQBuAF
QAZQB4AHQAIAAtAEYAbwByAGMAZQAKAEUAeABwAG8AcgB0AC0AUABmAHgAQwBlAHIAdABpAGYAaQBjAGEAdABlACAALQBDAGUAcgB0ACAAJABjAGUAcgB0A
GkAZgBpAGMAYQB0AGUAIAAtAEYAaQBsAGUAUABhAHQAaAAgAGMAOgBcAGkAbgB0AHUAbgBlAC4AcABmAHgAIAAtAFAAYQBzAHMAdwBvAHIAZAAgACQAcABh
AHMAcwB3AG8AcgBkAAoASQBtAHAAbwByAHQALQBQAGYAeABDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIAAtAEUAeABwAG8AcgB0AGEAYgBsAGUAIAAtAFAAYQB
zAHMAdwBvAHIAZAAgACQAcABhAHMAcwB3AG8AcgBkACAALQBDAGUAcgB0AFMAdABvAHIAZQBMAG8AYwBhAHQAaQBvAG4AIABDAGUAcgB0ADoAXABMAG8AYw
BhAGwATQBhAGMAaABpAG4AZQBcAE0AeQAgAC0ARgBpAGwAZQBQAGEAdABoACAAYwA6AFwAaQBuAHQAdQBuAGUALgBwAGYAeAA="'
                }else{
                        Write-Host 'You dont like me fixing it...?Fine...exiting now' -foregroundcolor red
                    read-Host -prompt "Press any key to continue..."
                    exit
                }
}    

function check-certdate {
            Write-Host "Checking If the Certificate hasn't expired" -foregroundcolor yellow
            if ((Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -eq $thumbprint -and 
$_.NotAfter -lt (Get-Date)}) -eq $null)
            {
                Write-Host "Great!!! The Intune Device Certificate is not expired!! WOOP WOOP" -foregroundcolor green
            }else{
                Write-Host "Is this a shitstorm? because the Intune Device Certificate is EXPIRED!" -foregroundcolor 
red
                fix-certificate
            }
}



function check-intunecert{
                if (Get-ChildItem Cert:\LocalMachine\My\ | where{$_.issuer -like "*Microsoft Intune MDM Device CA*"}){
                write-Host "Intune Device Certificate is in installed in the Local Machine Certificate store" 
-foregroundcolor green
                }else{
                Write-Host "Intune device Certificate still seems to be missing... sorry!" -foregroundcolor red    
                }
}


function fix-certificate { 
                $title    = 'Fixing the Intune Enrollment'
                $question = 'Are you 100% sure you want to proceed? Because I will break everything...or not!!!!!'
                $choices  = '&Yes', '&No'
                $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
                
                if ($decision -eq 0){
                        $progressPreference = 'silentlyContinue'
                            write-host "Trying to enroll your device into Intune or something else..." 
-foregroundcolor yellow
                        fix-mdmurls
                        Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/PSTools.zip' -OutFile 
'pstools.zip'
                        Expand-Archive -Path 'pstools.zip' -DestinationPath "$env:TEMP\pstools" -force
                        #Move-Item -Path "$env:TEMP\pstools\psexec.exe" -force
                        reg.exe ADD HKCU\Software\Sysinternals /v EulaAccepted /t REG_DWORD /d 1 /f | out-null
                        $enroll = Start-Process -windowstyle hidden -FilePath "$env:TEMP\pstools\psexec.exe" 
-ArgumentList '-s cmd /c "powershell.exe -ExecutionPolicy Bypass -encodedcommand JABSAGUAZwBpAHMAdAByAHkASwBlAHkAcwAgAD
0AIAAiAEgASwBMAE0AOgBcAFMATwBGAFQAVwBBAFIARQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwARQBuAHIAbwBsAGwAbQBlAG4AdABzACIALAAgACIASABLA
EwATQA6AFwAUwBPAEYAVABXAEEAUgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABFAG4AcgBvAGwAbABtAGUAbgB0AHMAXABTAHQAYQB0AHUAcwAiACwAIgBI
AEsATABNADoAXABTAE8ARgBUAFcAQQBSAEUAXABNAGkAYwByAG8AcwBvAGYAdABcAEUAbgB0AGUAcgBwAHIAaQBzAGUAUgBlAHMAbwB1AHIAYwBlAE0AYQB
uAGEAZwBlAHIAXABUAHIAYQBjAGsAZQBkACIALAAgACIASABLAEwATQA6AFwAUwBPAEYAVABXAEEAUgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABQAG8AbA
BpAGMAeQBNAGEAbgBhAGcAZQByAFwAQQBkAG0AeABJAG4AcwB0AGEAbABsAGUAZAAiACwAIAAiAEgASwBMAE0AOgBcAFMATwBGAFQAVwBBAFIARQBcAE0Aa
QBjAHIAbwBzAG8AZgB0AFwAUABvAGwAaQBjAHkATQBhAG4AYQBnAGUAcgBcAFAAcgBvAHYAaQBkAGUAcgBzACIALAAiAEgASwBMAE0AOgBcAFMATwBGAFQA
VwBBAFIARQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAUAByAG8AdgBpAHMAaQBvAG4AaQBuAGcAXABPAE0AQQBEAE0AXABBAGMAYwBvAHUAbgB0AHMAIgAsACA
AIgBIAEsATABNADoAXABTAE8ARgBUAFcAQQBSAEUAXABNAGkAYwByAG8AcwBvAGYAdABcAFAAcgBvAHYAaQBzAGkAbwBuAGkAbgBnAFwATwBNAEEARABNAF
wATABvAGcAZwBlAHIAIgAsACAAIgBIAEsATABNADoAXABTAE8ARgBUAFcAQQBSAEUAXABNAGkAYwByAG8AcwBvAGYAdABcAFAAcgBvAHYAaQBzAGkAbwBuA
GkAbgBnAFwATwBNAEEARABNAFwAUwBlAHMAcwBpAG8AbgBzACIACgAKACQARQBuAHIAbwBsAGwAbQBlAG4AdABJAEQAIAA9ACAARwBlAHQALQBTAGMAaABl
AGQAdQBsAGUAZABUAGEAcwBrACAALQB0AGEAcwBrAG4AYQBtAGUAIAAnAFAAdQBzAGgATABhAHUAbgBjAGgAJwAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwB
uACAAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAgAHwAIABXAGgAZQByAGUALQBPAGIAagBlAGMAdAAgAHsAJABfAC4AVABhAHMAawBQAGEAdA
BoACAALQBsAGkAawBlACAAIgAqAE0AaQBjAHIAbwBzAG8AZgB0ACoAVwBpAG4AZABvAHcAcwAqAEUAbgB0AGUAcgBwAHIAaQBzAGUATQBnAG0AdAAqACIAf
QAgAHwAIABTAGUAbABlAGMAdAAtAE8AYgBqAGUAYwB0ACAALQBFAHgAcABhAG4AZABQAHIAbwBwAGUAcgB0AHkAIABUAGEAcwBrAFAAYQB0AGgAIAAtAFUA
bgBpAHEAdQBlACAAfAAgAFcAaABlAHIAZQAtAE8AYgBqAGUAYwB0ACAAewAkAF8AIAAtAGwAaQBrAGUAIAAiACoALQAqAC0AKgAiAH0AIAB8ACAAUwBwAGw
AaQB0AC0AUABhAHQAaAAgAC0ATABlAGEAZgAKAAoACQAJAGYAbwByAGUAYQBjAGgAIAAoACQASwBlAHkAIABpAG4AIAAkAFIAZQBnAGkAcwB0AHIAeQBLAG
UAeQBzACkAIAB7AAoACQAJAAkACQBpAGYAIAAoAFQAZQBzAHQALQBQAGEAdABoACAALQBQAGEAdABoACAAJABLAGUAeQApACAAewAKAAkACQAJAAkACQBnA
GUAdAAtAEMAaABpAGwAZABJAHQAZQBtACAALQBQAGEAdABoACAAJABLAGUAeQAgAHwAIABXAGgAZQByAGUALQBPAGIAagBlAGMAdAAgAHsAJABfAC4ATgBh
AG0AZQAgAC0AbQBhAHQAYwBoACAAJABFAG4AcgBvAGwAbABtAGUAbgB0AEkARAB9ACAAfAAgAFIAZQBtAG8AdgBlAC0ASQB0AGUAbQAgAC0AUgBlAGMAdQB
yAHMAZQAgAC0ARgBvAHIAYwBlACAALQBDAG8AbgBmAGkAcgBtADoAJABmAGEAbABzAGUAIAAtAEUAcgByAG8AcgBBAGMAdABpAG8AbgAgAFMAaQBsAGUAbg
B0AGwAeQBDAG8AbgB0AGkAbgB1AGUACgAJAH0ACgB9AAoAJABJAG4AdAB1AG4AZQBDAGUAcgB0ACAAPQAgAEcAZQB0AC0AQwBoAGkAbABkAEkAdABlAG0AI
AAtAFAAYQB0AGgAIABDAGUAcgB0ADoAXABMAG8AYwBhAGwATQBhAGMAaABpAG4AZQBcAE0AeQAgAHwAIABXAGgAZQByAGUALQBPAGIAagBlAGMAdAAgAHsA
CgAJAAkAJABfAC4ASQBzAHMAdQBlAHIAIAAtAG0AYQB0AGMAaAAgACIASQBuAHQAdQBuAGUAIABNAEQATQAiACAACgAJAH0AIAB8ACAAUgBlAG0AbwB2AGU
ALQBJAHQAZQBtAAoAaQBmACAAKAAkAEUAbgByAG8AbABsAG0AZQBuAHQASQBEACAALQBuAGUAIAAkAG4AdQBsAGwAKQAgAHsAIAAKAAkAZgBvAHIAZQBhAG
MAaAAgACgAJABlAG4AcgBvAGwAbABtAGUAbgB0ACAAaQBuACAAJABlAG4AcgBvAGwAbABtAGUAbgB0AGkAZAApAHsACgAJAAkACQBHAGUAdAAtAFMAYwBoA
GUAZAB1AGwAZQBkAFQAYQBzAGsAIAB8ACAAVwBoAGUAcgBlAC0ATwBiAGoAZQBjAHQAIAB7ACQAXwAuAFQAYQBzAGsAcABhAHQAaAAgAC0AbQBhAHQAYwBo
ACAAJABFAG4AcgBvAGwAbABtAGUAbgB0AH0AIAB8ACAAVQBuAHIAZQBnAGkAcwB0AGUAcgAtAFMAYwBoAGUAZAB1AGwAZQBkAFQAYQBzAGsAIAAtAEMAbwB
uAGYAaQByAG0AOgAkAGYAYQBsAHMAZQAKAAkACQAJACQAcwBjAGgAZQBkAHUAbABlAE8AYgBqAGUAYwB0ACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIA
AtAEMAbwBtAE8AYgBqAGUAYwB0ACAAcwBjAGgAZQBkAHUAbABlAC4AcwBlAHIAdgBpAGMAZQAKAAkACQAJACQAcwBjAGgAZQBkAHUAbABlAE8AYgBqAGUAY
wB0AC4AYwBvAG4AbgBlAGMAdAAoACkACgAJAAkACQAkAHIAbwBvAHQARgBvAGwAZABlAHIAIAA9ACAAJABzAGMAaABlAGQAdQBsAGUATwBiAGoAZQBjAHQA
LgBHAGUAdABGAG8AbABkAGUAcgAoACIAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAXABFAG4AdABlAHIAcAByAGkAcwBlAE0AZwBtAHQ
AIgApAAoACQAJAAkAJAByAG8AbwB0AEYAbwBsAGQAZQByAC4ARABlAGwAZQB0AGUARgBvAGwAZABlAHIAKAAkAEUAbgByAG8AbABsAG0AZQBuAHQALAAkAG
4AdQBsAGwAKQAKAH0AIAAKAH0AIAAKAAoAJABFAG4AcgBvAGwAbABtAGUAbgB0AEkARABNAEQATQAgAD0AIABHAGUAdAAtAFMAYwBoAGUAZAB1AGwAZQBkA
FQAYQBzAGsAIAB8ACAAVwBoAGUAcgBlAC0ATwBiAGoAZQBjAHQAIAB7ACQAXwAuAFQAYQBzAGsAUABhAHQAaAAgAC0AbABpAGsAZQAgACIAKgBNAGkAYwBy
AG8AcwBvAGYAdAAqAFcAaQBuAGQAbwB3AHMAKgBFAG4AdABlAHIAcAByAGkAcwBlAE0AZwBtAHQAKgAiAH0AIAB8ACAAUwBlAGwAZQBjAHQALQBPAGIAagB
lAGMAdAAgAC0ARQB4AHAAYQBuAGQAUAByAG8AcABlAHIAdAB5ACAAVABhAHMAawBQAGEAdABoACAALQBVAG4AaQBxAHUAZQAgAHwAIABXAGgAZQByAGUALQ
BPAGIAagBlAGMAdAAgAHsAJABfACAALQBsAGkAawBlACAAIgAqAC0AKgAtACoAIgB9ACAAfAAgAFMAcABsAGkAdAAtAFAAYQB0AGgAIAAtAEwAZQBhAGYAC
gAJAAkAZgBvAHIAZQBhAGMAaAAgACgAJABLAGUAeQAgAGkAbgAgACQAUgBlAGcAaQBzAHQAcgB5AEsAZQB5AHMAKQAgAHsACgAJAAkACQAJAGkAZgAgACgA
VABlAHMAdAAtAFAAYQB0AGgAIAAtAFAAYQB0AGgAIAAkAEsAZQB5ACkAIAB7AAoACQAJAAkACQAJAGcAZQB0AC0AQwBoAGkAbABkAEkAdABlAG0AIAAtAFA
AYQB0AGgAIAAkAEsAZQB5ACAAfAAgAFcAaABlAHIAZQAtAE8AYgBqAGUAYwB0ACAAewAkAF8ALgBOAGEAbQBlACAALQBtAGEAdABjAGgAIAAkAEUAbgByAG
8AbABsAG0AZQBuAHQASQBEAE0ARABNAH0AIAB8ACAAUgBlAG0AbwB2AGUALQBJAHQAZQBtACAALQBSAGUAYwB1AHIAcwBlACAALQBGAG8AcgBjAGUAIAAtA
EMAbwBuAGYAaQByAG0AOgAkAGYAYQBsAHMAZQAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAK
AAkAfQAKAH0ACgBpAGYAIAAoACQARQBuAHIAbwBsAGwAbQBlAG4AdABJAEQATQBEAE0AIAAtAG4AZQAgACQAbgB1AGwAbAApACAAewAgAAoACQBmAG8AcgB
lAGEAYwBoACAAKAAkAGUAbgByAG8AbABsAG0AZQBuAHQAIABpAG4AIAAkAGUAbgByAG8AbABsAG0AZQBuAHQAaQBkAE0ARABNACkAewAKAAkACQAJAEcAZQ
B0AC0AUwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawAgAHwAIABXAGgAZQByAGUALQBPAGIAagBlAGMAdAAgAHsAJABfAC4AVABhAHMAawBwAGEAdABoACAAL
QBtAGEAdABjAGgAIAAkAEUAbgByAG8AbABsAG0AZQBuAHQAfQAgAHwAIABVAG4AcgBlAGcAaQBzAHQAZQByAC0AUwBjAGgAZQBkAHUAbABlAGQAVABhAHMA
awAgAC0AQwBvAG4AZgBpAHIAbQA6ACQAZgBhAGwAcwBlAAoACQAJAAkAJABzAGMAaABlAGQAdQBsAGUATwBiAGoAZQBjAHQAIAA9ACAATgBlAHcALQBPAGI
AagBlAGMAdAAgAC0AQwBvAG0ATwBiAGoAZQBjAHQAIABzAGMAaABlAGQAdQBsAGUALgBzAGUAcgB2AGkAYwBlAAoACQAJAAkAJABzAGMAaABlAGQAdQBsAG
UATwBiAGoAZQBjAHQALgBjAG8AbgBuAGUAYwB0ACgAKQAKAAkACQAJACQAcgBvAG8AdABGAG8AbABkAGUAcgAgAD0AIAAkAHMAYwBoAGUAZAB1AGwAZQBPA
GIAagBlAGMAdAAuAEcAZQB0AEYAbwBsAGQAZQByACgAIgBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwBcAEUAbgB0AGUAcgBwAHIAaQBz
AGUATQBnAG0AdAAiACkACgAJAAkACQAkAHIAbwBvAHQARgBvAGwAZABlAHIALgBEAGUAbABlAHQAZQBGAG8AbABkAGUAcgAoACQARQBuAHIAbwBsAGwAbQB
lAG4AdAAsACQAbgB1AGwAbAApAAoAfQAgAAoAJABJAG4AdAB1AG4AZQBDAGUAcgB0ACAAPQAgAEcAZQB0AC0AQwBoAGkAbABkAEkAdABlAG0AIAAtAFAAYQ
B0AGgAIABDAGUAcgB0ADoAXABMAG8AYwBhAGwATQBhAGMAaABpAG4AZQBcAE0AeQAgAHwAIABXAGgAZQByAGUALQBPAGIAagBlAGMAdAAgAHsACgAJAAkAJ
ABfAC4ASQBzAHMAdQBlAHIAIAAtAG0AYQB0AGMAaAAgACIATQBpAGMAcgBvAHMAbwBmAHQAIABEAGUAdgBpAGMAZQAgAE0AYQBuAGEAZwBlAG0AZQBuAHQA
IABEAGUAdgBpAGMAZQAgAEMAQQAiACAACgAJAH0AIAB8ACAAUgBlAG0AbwB2AGUALQBJAHQAZQBtAAoAfQAJAAoAUwB0AGEAcgB0AC0AUwBsAGUAZQBwACA
ALQBTAGUAYwBvAG4AZABzACAANQAKACQARQBuAHIAbwBsAGwAbQBlAG4AdABQAHIAbwBjAGUAcwBzACAAPQAgAFMAdABhAHIAdAAtAFAAcgBvAGMAZQBzAH
MAIAAtAEYAaQBsAGUAUABhAHQAaAAgACIAQwA6AFwAVwBpAG4AZABvAHcAcwBcAFMAeQBzAHQAZQBtADMAMgBcAEQAZQB2AGkAYwBlAEUAbgByAG8AbABsA
GUAcgAuAGUAeABlACIAIAAtAEEAcgBnAHUAbQBlAG4AdABMAGkAcwB0ACAAIgAvAEMAIAAvAEEAdQB0AG8AZQBuAHIAbwBsAGwATQBEAE0AIgAgAC0ATgBv
AE4AZQB3AFcAaQBuAGQAbwB3ACAALQBXAGEAaQB0ACAALQBQAGEAcwBzAFQAaAByAHUACgA="' 
                        $enroll
                        write-host "`n"

                        write-host "Please give the OMA DM client some time (about 30 seconds)to sync and get your 
device enrolled into Intune" -foregroundcolor yellow
                        write-host "`n"
                        start-sleep -seconds 30
                        write-host "Checking the Intune Certificate Again!." -foregroundcolor yellow
                        check-intunecert
                        check-dmwapservice
                        Get-ScheduledTask | ? {$_.TaskName -eq 'Schedule #1 created by enrollment client'} | 
Start-ScheduledTask
                        start-sleep -seconds 10
                        $Shell = New-Object -ComObject Shell.Application
                        $Shell.open("intunemanagementextension://syncapp")
                        check-dmpcert
                        start-sleep -seconds 5
                        get-schedule1
                        read-Host -prompt "Press any key to continue..."
                        exit    
                        }else{
                            write-host "`n"
                                Write-Host 'You dont like me fixing it...? Fine...exiting now' -fo1:48 AM 
3/22/2023regroundcolor red
                            exit 1
                             }
}



function fix-privatekey {                 
                $title    = 'Intune Private Key'
                $question = 'Are you sure you want to fix the private key missing??'
                $choices  = '&Yes', '&No'
                $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
                
                if ($decision -eq 0) {
                                Write-Host "List certificates without private key: " -NoNewline
                            $certsWithoutKey = Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.HasPrivateKey 
-eq $false}
                            
                            if($certsWithoutKey) {
                                    Write-Host "V" -ForegroundColor Green
                                    $Choice = $certsWithoutKey | Select-Object Subject, Issuer, NotAfter, ThumbPrint | 
Out-Gridview -Passthru
                                    
                                if($Choice){
                                        Write-Host "Search private key for $($Choice.Thumbprint): " -NoNewline
                                        $Output = certutil -repairstore my "$($Choice.Thumbprint)"
                                        $Result = [regex]::match($output, "CertUtil: (.*)").Groups[1].Value
                                        
                                    if($Result -eq '-repairstore command completed successfully.') {
                                               Write-Host "V" -ForegroundColor Green
                                       }else{
                                            Write-Host $Result -ForegroundColor Red
                                        }
                                       }else{
                                    Write-Host "No choice was made." -ForegroundColor DarkYellow
                                    }
                            }else{
                               Write-Host "There were no certificates found without private key." -ForegroundColor 
DarkYellow
                            }
                        }else{
                               Write-Host 'You cancelled the fix... why?' -foregroundcolor red
                            Write-Host "Press any key to continue..."
                            $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                            exit 1
                        }
}


function get-privatekey{ 
                if ((Get-ChildItem Cert:\LocalMachine\My | where {$_.Thumbprint -match $thumbprint}).HasPrivateKey){
                 Write-Host "Nice.. your Intune Device Certificate still has its private key" -foregroundcolor green
                }else{
                Write-Host "I guess we need to fix something because the certificate is missing its private key"  
-foregroundcolor red 
                fix-privatekey
                }
}


function check-mdmlog{
Write-Host "Hold on a moment... Initializing a sync and checking the MDM logs for sync errors!"  -foregroundcolor 
yellow
$Shell = New-Object -ComObject Shell.Application
$Shell.open("intunemanagementextension://syncapp")
start-sleep -seconds 5

Remove-Item -Path $env:TEMP\diag\* -Force -ErrorAction SilentlyContinue 
Start-Process MdmDiagnosticsTool.exe -Wait -ArgumentList "-out $env:TEMP\diag\" -NoNewWindow

$checkmdmlog = Select-String -Path $env:TEMP\diag\MDMDiagReport.html -Pattern "The last sync failed"
    if($checkmdmlog -eq $null){
                        Write-Host "Not detecting any sync errors in the MDM log" -foregroundcolor green
                    }else{
                         Write-Host "It's a good thing you are running this script because you do have some Intune 
sync issues going on"  -foregroundcolor red 
                        }
}


function check-imelog{ 
                $path = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\IntuneManagementExtension.log"
                 If(Test-Path $path) 
                    { 
                        $checklog = Select-String -Path 
'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\IntuneManagementExtension.log' -Pattern "Set 
MdmDeviceCertificate : $thumbprint"
                            if ($checklog -ne $null){
                               Write-Host "I guess you need to quit your job and go to the casino as the proper Intune 
certificate with $thumbprint is also mentioned in the IME" -foregroundcolor green
                            }else{
                                $checklogzero = Select-String -Path 
'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\IntuneManagementExtension.log' -Pattern "Find 0 MDM 
certificates"
                                $firstline = $checklogzero | select-object -first 1         
                                Write-Host "Ow my.. this is could not be a good thing... $firstline"  -foregroundcolor 
red 
                            }
                    } Else { Write-Host "Uhhhhh... the log is missing... it seems the IME is not installed"  
-foregroundcolor red}
                    check-imeservice
}
 


function check-dmpcert{
                write-host "`n"
                write-host "Determing if the certificate mentioned in the SSLClientCertreference is also configured in 
the Enrollments part of the registry " -foregroundcolor yellow
                    try{     
                    $ProviderRegistryPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments"
                    $ProviderPropertyName = "ProviderID"
                    $ProviderPropertyValue = "MS DM Server"
                    $GUID = (Get-ChildItem -Path Registry::$ProviderRegistryPath -Recurse -ErrorAction 
SilentlyContinue | ForEach-Object { if((Get-ItemProperty -Name $ProviderPropertyName -Path $_.PSPath -ErrorAction 
SilentlyContinue | Get-ItemPropertyValue -Name $ProviderPropertyName -ErrorAction SilentlyContinue) -match 
$ProviderPropertyValue) { $_ } }).PSChildName
                    $cert = (Get-ChildItem Cert:\LocalMachine\My\ | where{$_.issuer -like "*Microsoft Intune MDM 
Device CA*"})
                    $certthumbprint = $cert.thumbprint
                    $certsubject = $cert.subject
                    $subject = $certsubject -replace "CN=",""
                     }
                catch {
                     Write-host "Failed to get guid for enrollment from registry, device doesnt seem enrolled?" 
-foregroundcolor red
                    } 

if((Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Enrollments\$guid").DMPCertThumbPrint -eq $certthumbprint){
        Write-Host "Great!!! The Intune Device Certificate with the Thumbprint $certthumbprint is configured in the 
registry Enrollments" -foregroundcolor green
    }else{
        Write-Host "Intune Device Certificate is not configured in the Registry Enrollments" -foregroundcolor red
        }
}


function get-sslclientcertreference{
                    try{ 
                        $ProviderRegistryPath = "HKLM:SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\"
                        $ProviderPropertyName = "ServerVer"
                        $ProviderPropertyValue = "4.0"
                        $GUID = (Get-ChildItem -Path $ProviderRegistryPath -Recurse -ErrorAction SilentlyContinue | 
ForEach-Object { if((Get-ItemProperty -Name $ProviderPropertyName -Path $_.PSPath -ErrorAction SilentlyContinue | 
Get-ItemPropertyValue -Name $ProviderPropertyName -ErrorAction SilentlyContinue) -match $ProviderPropertyValue) { $_ } 
}).PSChildName
                        $ssl = (Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\$guid" 
-ErrorAction SilentlyContinue).sslclientcertreference
                        } 
                    catch [System.Exception] {
                                      Write-Error "Failed to get Enrollment GUID or SSL Client Reference for 
enrollment from registry, device doesnt seem enrolled or it needs a reboot first" 
                                      $result = $false
                        }

                        if ($ssl -eq $null){
                                    Write-Host "Thats weird, your device doesnt seem to be enrolled into Intune, lets 
find out why!.. hold my beer!" -foregroundcolor red
                        }else{
                                    Write-Host "Device seems to be Enrolled into Intune... proceeding" 
-foregroundcolor green
                    }                        
}



function check-imeservice{
                write-host "`n"
                write-host "Determing if the IME service is succesfully installed" -foregroundcolor yellow
$path = "C:\Program Files (x86)\Microsoft Intune Management 
Extension\Microsoft.Management.Services.IntuneWindowsAgent.exe"
If(Test-Path $path) { 
                write-host "IntuneWindowsAgent.exe is available on the device"-foregroundcolor green
                write-host "Going to check if the IME service is installed" -foregroundcolor yellow
                $service = Get-Service -Name IntuneManagementExtension -ErrorAction SilentlyContinue
                if ($service.Length -gt 0) {
                    Write-Host "jippie ka yee, the IME service seems to be installed!" -foregroundcolor green
                    }else{
                                    Write-Host "Mmm okay.. The IME software isn't installed" -foregroundcolor red
                     }
                }else{
                    write-host "IntuneWindowsAgent.exe seems to be missing, checking if its even installed" 
-foregroundcolor red
                        if((Get-WmiObject -Class Win32_Product).caption -eq "Microsoft Intune Management Extension"){ 
                            Write-Host "jippie ka yee, the IME software seems to be installed!" -foregroundcolor green
                                }else{
                                    Write-Host "Mmm okay.. The IME software isn't installed" -foregroundcolor red
                                        $title    = 'Fixing the IME'
                                        $question = 'Are you 100% sure you want to proceed?!!!!!'
                                        $choices  = '&Yes', '&No'
                                        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
                
                                        if ($decision -eq 0){
                                            $ProviderRegistryPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\EnterpriseDe
sktopAppManagement\S-0-0-00-0000000000-0000000000-000000000-000\MSI"    
                                            $ProviderPropertyName = "CurrentDownloadUrl"        
                                            $ProviderPropertyValue = "*IntuneWindowsAgent.msi*"    
                                            $GUID = (Get-ChildItem -Path Registry::$ProviderRegistryPath -Recurse 
-ErrorAction SilentlyContinue | ForEach-Object { if((Get-ItemProperty -Name $ProviderPropertyName -Path $_.PSPath 
-ErrorAction SilentlyContinue | Get-ItemPropertyValue -Name $ProviderPropertyName -ErrorAction SilentlyContinue) -like 
$ProviderPropertyValue) { $_ } }).pschildname | select-object -first 1                      
                                            $link = Get-ItemProperty -Path 
HKLM:\SOFTWARE\Microsoft\EnterpriseDesktopAppManagement\S-0-0-00-0000000000-0000000000-000000000-000\MSI\$GUID         
           
                                            $link = $link.currentdownloadurl                    
                                            Invoke-WebRequest -Uri $link -OutFile 'IntuneWindowsAgent.msi'             
       
                                            .\IntuneWindowsAgent.msi /quiet
                                        }else{
                                            write-host "`n"
                                                Write-Host 'You dont like me fixing it...? Fine...exiting now' 
-foregroundcolor red
                                            
                                                 }                

                                    }

                }
}



function check-entdmid{
                write-host "`n"
                write-host "Determing if the certificate subject is also configured in the EntDMID key " 
-foregroundcolor yellow
                    try{     
                    $ProviderRegistryPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments"
                    $ProviderPropertyName = "ProviderID"
                    $ProviderPropertyValue = "MS DM Server"
                    $GUID = (Get-ChildItem -Path Registry::$ProviderRegistryPath -Recurse -ErrorAction 
SilentlyContinue | ForEach-Object { if((Get-ItemProperty -Name $ProviderPropertyName -Path $_.PSPath -ErrorAction 
SilentlyContinue | Get-ItemPropertyValue -Name $ProviderPropertyName -ErrorAction SilentlyContinue) -match 
$ProviderPropertyValue) { $_ } }).PSChildName
                    $cert = (Get-ChildItem Cert:\LocalMachine\My\ | where{$_.issuer -like "*Microsoft Intune MDM 
Device CA*"})
                    $certthumbprint = $cert.thumbprint
                    $certsubject = $cert.subject
                    $subject = $certsubject -replace "CN=",""
                     }
                catch {
                     Write-host "Failed to get guid for enrollment from registry, device doesnt seem enrolled?" 
-foregroundcolor red
                    } 

if((Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Enrollments\$guid\DMClient\MS DM Server").entdmid -eq $subject){
        Write-Host "I have good news!! The subject of the Intune Certificate is also set in the EntDMID registry key. 
Let's party!!!!" -foregroundcolor green
    }else{
        Write-Host "I have some shitty news! The EntDMID key is not configured, you probably need to reboot the device 
and run the test again" -foregroundcolor red
        }
}


function check-dmwapservice{
                    write-host "`n"
                    write-host "Determing if the dmwappushservice is running because we don't want to end up with no 
endpoints left to the endpointmapper" -foregroundcolor yellow
                    $ServiceName = "dmwappushservice"
                    $ServiceStatus = (Get-Service -Name $ServiceName).status
                        if($ServiceStatus -eq "Running")
                        {
                               Write-Host "I am happy...! The DMWAPPUSHSERVICE is Running!" -foregroundcolor green
                                                    }
                        else {
                                   Write-Host "The DMWAPPUSHSERVICE isn't running, let's kickstart that damn service 
to speed up the enrollment! " -foregroundcolor red
                                   Start-Service $Servicename -ErrorAction SilentlyContinue    
                            }
}

function get-schedule1 {
write-host "Almost finished, checking if the EnterpriseMGT tasks are running to start the sync!" -foregroundcolor 
yellow
If ((Get-ScheduledTask | Where TaskName -eq 'Schedule #1 created by enrollment client').State -eq 'running')
    {
    write-host "`n"
    write-host "Enrollment task is running! It looks like I fixed your sync issues.I guess you owe me a membeer now!" 
-foregroundcolor green
    $Form.ShowDialog()
    }elseif ((Get-ScheduledTask | Where TaskName -eq 'Schedule #1 created by enrollment client').State -eq 'ready') 
    {
    write-host "Enrollment task is ready!!!" -foregroundcolor green
    }else{
   write-host "Enrollment task doesn't exist" -foregroundcolor red
}
}


function fix-mdmurls{
            write-host "`n"
            write-host "Determing if the required MDM enrollment urls are configured in the registry" -foregroundcolor 
yellow

            $key = 'SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo\*' 
            $keyinfo = Get-Item "HKLM:\$key" -ErrorAction Ignore
            $url = $keyinfo.name
            $url = $url.Split("\")[-1]
            $path = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo\$url" 

if (test-path $path){
$mdmurl = get-itemproperty -LiteralPath $path -Name 'MdmEnrollmentUrl'
$mdmurl = $mdmurl.mdmenrollmenturl
}else{
    write-host "I guess I am missing the proper tenantinfo" -foregroundcolor red 
            }


if($mdmurl -eq "https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc"){
        write-host "MDM Enrollment URLS are configured the way I like it!Nice!!" -foregroundcolor green
        
}else{
    write-host "MDM enrollment url's are missing! Let me get my wrench and fix it for you!" -foregroundcolor red 
    New-ItemProperty -LiteralPath $path -Name 'MdmEnrollmentUrl' -Value 
'https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc' -PropertyType String -Force -ea 
SilentlyContinue;
    New-ItemProperty -LiteralPath $path  -Name 'MdmTermsOfUseUrl' -Value 
'https://portal.manage.microsoft.com/TermsofUse.aspx' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath $path -Name 'MdmComplianceUrl' -Value 
'https://portal.manage.microsoft.com/?portalAction=Compliance' -PropertyType String -Force -ea SilentlyContinue;

            
            }
}

##################################################################
###############starting the reallll script########################
##################################################################
$RegistryKeys = "HKLM:\SOFTWARE\Microsoft\Enrollments", 
"HKLM:\SOFTWARE\Microsoft\Enrollments\Status","HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked", 
"HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled", 
"HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers","HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts", 
"HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger", "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Sessions"

#fetching the enrollmentid
$EnrollmentID = Get-ScheduledTask -taskname 'PushLaunch' | Where-Object {$_.TaskPath -like 
"*Microsoft*Windows*EnterpriseMgmt*"} | Select-Object -ExpandProperty TaskPath -Unique | Where-Object {$_ -like 
"*-*-*"} | Split-Path -Leaf

check-mdmlog
write-host "`n"
write-host "Determining if the device is enrolled and fetching the SSLClientCertReference registry key" 
-foregroundcolor yellow
try{ 
    $ProviderRegistryPath = "HKLM:SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\$EnrollmentID"
    $ProviderPropertyName = "SslClientCertReference"
    $GUID = (Get-Item -Path $ProviderRegistryPath -ErrorAction SilentlyContinue | ForEach-Object { 
if((Get-ItemProperty -Name $ProviderPropertyName -Path $_.PSPath -ErrorAction SilentlyContinue | Get-ItemPropertyValue 
-Name $ProviderPropertyName -ErrorAction SilentlyContinue)) { $_ } }).PSChildName
    $ssl = (Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\$guid" -ErrorAction 
SilentlyContinue).sslclientcertreference
    } 
catch [System.Exception] {
                Write-Error "Failed to get Enrollment GUID or SSL Client Reference for enrollment from registry... 
that's odd almost as if the Intune Certificate is gone" 
                  $result = $false
                }
    if ($ssl -eq $null){
                Write-Host "Thats weird, your device doesnt seem to be enrolled into Intune, lets find out why!.. hold 
my beer!" -foregroundcolor red
    }else{
                Write-Host "Device seems to be Enrolled into Intune... proceeding" -foregroundcolor green
        }

write-host "`n"
write-host "Checking the Certificate Prefix.. to find out if it is configured as SYSTEM or USER" -foregroundcolor 
yellow

try{
$thumbprintPrefix = "MY;System;"
$thumbprint = $ssl.Replace($thumbprintPrefix, "")         
if ($ssl.StartsWith($thumbprintPrefix) -eq $true)
{ 
          write-host "The Intune Certificate Prefix is configured as $thumbprintprefix" -foregroundcolor green
        write-host "`n"
        write-host "Determing if the certificate is installed in the local machine certificate store" -foregroundcolor 
yellow
    if (Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -eq $thumbprint}){
        Write-Host "Intune Device Certificate is installed in the Local Machine Certificate store" -foregroundcolor 
green
        write-host "`n"
        check-certdate
            write-host "`n"
            write-host "Checking if the Certificate is also mentioned in the IME log" -foregroundcolor yellow
            check-imelog
    }else{
        Write-Host "Intune device Certificate is missing in the Local Machine Certificate store" -foregroundcolor red  
  
        fix-certificate
            write-host "Running some tests to determine if the device has the SSLClientCertReference registry key 
configured!" -foregroundcolor yellow
            get-sslclientcertreference
    }
        write-host "`n"
        write-host "Determing if the certificate has a Private Key Attached" -foregroundcolor yellow
        get-privatekey
            check-dmpcert
}else{
    write-host "Damn... the SSL prefix is not configured as SYSTEM but as $SSL" -foregroundcolor red
    $thumbprintPrefix = "MY;User;"
    $thumbprint = $ssl.Replace($thumbprintPrefix, "")
    
    write-host "`n"
    write-host "Determing if the certificate is also not in the System Certificate Store" -foregroundcolor yellow
    
    if(Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -eq $thumbprint}){
        Write-Host "Intune Device Certificate is installed in the Local Machine Certificate store" -foregroundcolor 
green
        write-host "`n"
        check-certdate
            write-host "`n"
            write-host "Determing if the certificate has a Private Key Attached" -foregroundcolor yellow
            get-privatekey
            check-dmpcert
    }else{
        Write-Host "Intune device Certificate is installed in the wrong user store. I will fix it for you!" 
-foregroundcolor red
        fix-wrongstore
            write-host "Determing if the certificate is now been installed in the proper store" -foregroundcolor yellow
            check-intunecert
    }
}
}
catch {
      Write-host "Failed to get the Certificate Details, device doesnt seem enrolled? Who cares?Let's fix it" 
-foregroundcolor red
    fix-certificate
          
    }

check-entdmid  

