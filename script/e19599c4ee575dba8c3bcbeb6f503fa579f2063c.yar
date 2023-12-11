import "math"
import "pe"

rule hacktool_windows_cobaltstrike_powershell_2
{
	meta:
		description = "Detect the risk of  Malware Cobalt Strike Rule 10"
		os = "windows"
		filetype = "script"

	strings:
		$ps1 = "'System.dll'" ascii
		$ps2 = "Set-StrictMode -Version 2" ascii
		$ps3 = "GetProcAddress" ascii
		$ps4 = "start-job" ascii
		$ps5 = "VirtualAlloc" ascii

	condition:
		$ps2 at 0 and filesize <1000KB and all of ($ps*)
}
