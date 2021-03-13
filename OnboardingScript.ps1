# Version 1

# Download the package
function download() {$ProgressPreference="SilentlyContinue"; Invoke-WebRequest -Uri https://aka.ms/AzureConnectedMachineAgent -OutFile AzureConnectedMachineAgent.msi}
download

# Install the package
$exitCode = (Start-Process -FilePath msiexec.exe -ArgumentList @("/i", "AzureConnectedMachineAgent.msi" ,"/l*v", "installationlog.txt", "/qn") -Wait -Passthru).ExitCode
if($exitCode -ne 0) {
    $message=(net helpmsg $exitCode)
    throw "Installation failed: $message See installationlog.txt for additional details."
}

# Run connect command
& "$env:ProgramW6432\AzureConnectedMachineAgent\azcmagent.exe" connect --resource-group "AzureArc" --tenant-id "a494743f-7201-494d-a452-f48c5388c4c0" --location "eastus" --subscription-id "43ef7583-d005-4e60-8c4c-e3df3305b1e0" --cloud "AzureCloud" --correlation-id "303b3f75-8422-47dd-ac41-b1f6c09ad00b"

if($LastExitCode -eq 0){Write-Host -ForegroundColor yellow "To view your onboarded server(s), navigate to https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.HybridCompute%2Fmachines"}
