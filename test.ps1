#v1.2
#Deploiement Wazuh et Sysmon

#Declaration de variable Wazuh
$appli = "Wazuh Agent"
$check_wazuh_exist = Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -eq $appli}
$check_server = Get-WmiObject -Class Win32_OperatingSystem | Select-Object Caption
$WazuhTempFolder = "$env:TEMP\Wazuh"
$client = "FranceCyberdefense" #Remplir avec le nom de groupe du client dans Wazuh
$server = "master.francecyberdefense.fr" #A modifier si worker dédié
$master = "master.francecyberdefense.fr"
$servs = "$server,$master"
$lien = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.3-1.msi"

#Declaration de variable Sysmon
$VersionPattern = "v?(\d{2}\.\d{1,2})"
$SysmonTempFolder = "$env:TEMP\Sysmon"
$LogFile = "$env:TEMP\SysmonUpdate.log"
$config_file = "sysmon_config_medium.xml"
$check_sysmon_exist = Get-Service -Name Sysmon*

Function Get-SysmonLocation{
    return Get-ChildItem $env:SystemRoot -Filter Sysmon64.exe -ErrorAction SilentlyContinue | Select -First 1
}

Function New-TempEnvironmentSysmon{
    if(-not (Test-Path $SysmonTempFolder)){
        mkdir $SysmonTempFolder
        "Created $SysmonTempFolder"
    }
}
Function New-TempEnvironmentWazuh{
    if(-not (Test-Path $WazuhTempFolder)){
        mkdir $WazuhTempFolder
        "Created $SWazuhTempFolder"
    }
}

function Remove-TempEnvironmentSysmon{
    Get-ChildItem $SysmonTempFolder -Recurse | Remove-Item -Force
    Remove-Item $SysmonTempFolder
    "Removed $SysmonTempFolder and contents"
}

function Remove-TempEnvironmentWazuh{
    Get-ChildItem $WazuhTempFolder -Recurse | Remove-Item -Force
    Remove-Item $WazuhTempFolder
    "Removed $WazuhTempFolder and contents"
}

Function Download-SysmonZip{
    $URI = "https://download.sysinternals.com/files/Sysmon.zip"
    $Request = Invoke-WebRequest $Uri -OutFile $SysmonTempFolder\Sysmon.zip
    "Downloaded Sysmon.zip"
}

Function Unzip-File{
    Expand-Archive "$SysmonTempFolder\Sysmon.zip" -DestinationPath $SysmonTempFolder -Force -Verbose
    "Extracted Sysmon.zip to $SysmonTempFolder"
}


Function Install-Sysmon{
    & $SysmonTempFolder\Sysmon64.exe -i sysmonconfig-export.xml -accepteula
}

Function Retrieve-Config{
	Invoke-WebRequest -Uri https://raw.githubusercontent.com/FranceCyberDefense/sysmon-config/master/$config_file -Outfile sysmonconfig-export.xml
}

Get-Date | Tee-Object -FilePath $LogFile -Append

		

function Install-Wazuh-Agent {
	try{
Invoke-WebRequest -Uri $lien -OutFile $WazuhTempFolder\wazuh-agent
	}
	catch{
		Write-Warning -Message "Unable to download wazuh-agent"
	}
	try{
msiexec.exe /i $WazuhTempFolder\wazuh-agent /q WAZUH_MANAGER=$server WAZUH_AGENT_GROUP="$group" WAZUH_REGISTRATION_SERVER=$master
	}
	catch{
		Write-Warning -Message "Unable to deploy wazuh-agent"
	}

Sleep 5
NET START Wazuh
}

if(-not $check_sysmon_exist){
   New-TempEnvironmentSysmon | Tee-Object -FilePath $LogFile -Append
   Download-SysmonZip | Tee-Object -FilePath $LogFile -Append
   Retrieve-Config | Tee-Object -FilePath $LogFile -Append
   Unzip-File | Tee-Object -FilePath $LogFile -Append
   Install-Sysmon | Tee-Object -FilePath $LogFile -Append
   Remove-TempEnvironmentSysmon | Tee-Object -FilePath $LogFile -Append
} else {
    "Sysmon already exist." | Tee-Object -FilePath $LogFile -Append
}


If (-not $check_wazuh_exist)
{	
	if ($check_server -like '*serv*') {
			$group = "$client,Serveur,Windows"
		} else {
			$group = "$client,Workstation,Windows"
		}
	New-TempEnvironmentWazuh
	Install-Wazuh-Agent
	Remove-TempEnvironmentWazuh
}
