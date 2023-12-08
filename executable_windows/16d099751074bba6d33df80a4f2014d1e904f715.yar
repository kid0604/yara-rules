import "pe"

rule MALWARE_Win_QakBot
{
	meta:
		author = "ditekSHen"
		description = "Detects variants of QakBot payload"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "stager_1.dll" fullword ascii
		$s2 = "_vsnwprintf" fullword ascii
		$s3 = "DllRegisterServer" fullword ascii
		$s4 = "Win32_PnPEntity" fullword wide
		$s5 = "0>user32.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and all of them
}
