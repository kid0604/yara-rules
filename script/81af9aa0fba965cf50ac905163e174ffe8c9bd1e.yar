import "pe"

rule bazar_start_bat
{
	meta:
		description = "files - file start.bat"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com"
		date = "2021-01-25"
		hash1 = "63de40c7382bbfe7639f51262544a3a62d0270d259e3423e24415c370dd77a60"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "powershell.exe Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force" fullword ascii
		$x2 = "powershell.exe -executionpolicy remotesigned -File .\\Get-DataInfo.ps1 %1)" fullword ascii
		$x3 = "powershell.exe -executionpolicy remotesigned -File .\\Get-DataInfo.ps1 %method" fullword ascii
		$s4 = "set /p method=\"Press Enter for collect [all]: \"" fullword ascii
		$s5 = "echo \"all ping disk soft noping nocompress\"" fullword ascii
		$s6 = "echo \"Please select a type of info collected:\"" fullword ascii
		$s7 = "@echo on" fullword ascii
		$s8 = "color 07" fullword ascii
		$s9 = "pushd %~dp0" fullword ascii
		$s10 = "color 70" fullword ascii
		$s11 = "IF \"%1\"==\"\" (" fullword ascii
		$s12 = "IF NOT \"%1\"==\"\" (" fullword ascii

	condition:
		uint16(0)==0x6540 and filesize <1KB and 1 of ($x*) and all of them
}
