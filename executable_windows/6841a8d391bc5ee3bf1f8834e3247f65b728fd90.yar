import "pe"

rule MALWARE_Win_GENERIC02
{
	meta:
		author = "ditekSHen"
		description = "Detects known unamed malicious executables"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "{%s-%d-%d}" fullword wide
		$s2 = "update" fullword wide
		$s3 = "https://" fullword wide
		$s4 = "http://" fullword wide
		$s5 = "configure" fullword ascii
		$s6 = { 8d 4f 02 e8 8c ff ff ff 8b d8 81 fb 00 dc 00 00 }
		$s7 = { 83 c1 02 e8 3c ff ff ff 8b c8 ba ff 03 00 00 8d }

	condition:
		uint16(0)==0x5a4d and all of them
}
