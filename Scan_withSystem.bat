SET mypath=%~dp0
echo %mypath:~0,-1%
Powershell Set-ExecutionPolicy -ExecutionPolicy Unrestricted
%mypath:~0,-1%/psExec64.exe -s cmd /c "Powershell.exe %mypath:~0,-1%\get_hashes.ps1 "
Powershell Set-ExecutionPolicy -ExecutionPolicy restricted
  
pause
