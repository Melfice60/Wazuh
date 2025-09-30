:: Simple script to run  PShell script.
:: The script executes a powershell script and appends output.
@ECHO OFF
ECHO.

powershell.exe -executionpolicy ByPass -File "C:\Program Files (x86)\ossec-agent\active-response\bin\DNS-Sinkhole.ps1"

:Exit
