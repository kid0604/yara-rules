import "pe"

rule MALWARE_Win_BetaBot
{
	meta:
		author = "ditekSHen"
		description = "BetaBot payload"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "__restart" fullword ascii
		$s2 = "%SystemRoot%\\SysWOW64\\tapi3.dll" fullword wide
		$s3 = "%SystemRoot%\\system32\\tapi3.dll" fullword wide
		$s4 = "publicKeyToken=\"6595b64144ccf1df\"" ascii
		$s5 = "VirtualProtectEx" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <600KB and all of them
}
