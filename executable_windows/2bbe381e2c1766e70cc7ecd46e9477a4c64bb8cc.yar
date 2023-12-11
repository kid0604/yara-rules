import "pe"

rule MALWARE_Win_UnamedStealer
{
	meta:
		author = "ditekSHen"
		description = "Detects unknown infostealer. Observed as 2nd stage and injects into .NET AppLaunch.exe"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "HideMelt" fullword ascii
		$s2 = ".Implant" ascii
		$s3 = "SetUseragent" fullword ascii
		$s4 = "SendReport" fullword ascii
		$s5 = "cookiesList" fullword ascii
		$s6 = "WriteAppsList" fullword ascii
		$s7 = "Timeout /T 2 /Nobreak" fullword wide
		$s8 = "Directory not exists" wide
		$s9 = "### {0} ### ({1})" wide

	condition:
		uint16(0)==0x5a4d and 6 of them
}
