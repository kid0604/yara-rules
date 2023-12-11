import "pe"

rule MALWARE_Win_PolyglotDuke
{
	meta:
		author = "ditekSHen"
		description = "Detects PolyGlotDuke"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = { 48 b9 ff ff ff ff ff ff ff ff 51 48 23 8c 24 ?? 00 00 00 48 89 8C 24 00 00 00 00 }
		$s2 = { 56 be ff ff ff ff 56 81 e6 7f }
		$s3 = { 48 8b 05 19 ?4 4b 00 48 05 48 83 00 00 4c 8b 44 24 50 8b 54 24 48 48 8b }

	condition:
		uint16(0)==0x5a4d and ( all of ($s*)) or (2 of them and pe.exports("InitSvc"))
}
