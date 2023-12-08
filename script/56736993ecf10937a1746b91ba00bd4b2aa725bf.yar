rule SUSP_Disable_ETW_Jun20_1
{
	meta:
		description = "Detects method to disable ETW in ENV vars before executing a program"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://gist.github.com/Cyb3rWard0g/a4a115fd3ab518a0e593525a379adee3"
		date = "2020-06-06"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "set COMPlus_ETWEnabled=0" ascii wide fullword
		$x2 = "$env:COMPlus_ETWEnabled=0" ascii wide fullword
		$s1 = "Software\\Microsoft.NETFramework" ascii wide
		$sa1 = "/v ETWEnabled" ascii wide fullword
		$sa2 = " /d 0" ascii wide
		$sb4 = "-Name ETWEnabled"
		$sb5 = " -Value 0 "

	condition:
		1 of ($x*) or 3 of them
}
