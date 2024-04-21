rule case_5087_start_bat
{
	meta:
		description = "Files - file start.bat"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com"
		date = "2021-08-30"
		hash1 = "63de40c7382bbfe7639f51262544a3a62d0270d259e3423e24415c370dd77a60"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "powershell.exe Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force" fullword ascii
		$x2 = "powershell.exe -executionpolicy remotesigned -File .\\Get-DataInfo.ps1 %method" fullword ascii
		$x3 = "powershell.exe -executionpolicy remotesigned -File .\\Get-DataInfo.ps1 %1)" fullword ascii
		$s4 = "set /p method=\"Press Enter for collect [all]:  \"" fullword ascii
		$s5 = "echo \"Please select a type of info collected:\"" fullword ascii
		$s6 = "echo \"all ping disk soft noping nocompress\"" fullword ascii

	condition:
		filesize <1KB and all of them
}
