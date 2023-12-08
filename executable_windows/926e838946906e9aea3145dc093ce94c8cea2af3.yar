rule CN_Hacktool_MilkT_Scanner
{
	meta:
		description = "Detects a chinese Portscanner named MilkT"
		author = "Florian Roth"
		score = 60
		date = "12.10.2014"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Bf **************" ascii fullword
		$s1 = "forming Time: %d/" ascii
		$s2 = "KERNEL32.DLL" ascii fullword
		$s3 = "CRTDLL.DLL" ascii fullword
		$s4 = "WS2_32.DLL" ascii fullword
		$s5 = "GetProcAddress" ascii fullword
		$s6 = "atoi" ascii fullword

	condition:
		all of them
}
