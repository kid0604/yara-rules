import "pe"

rule SentinelSuperProAutomaticProtectionv641Safenet
{
	meta:
		author = "malware-lu"
		description = "Detects Sentinel SuperPro automatic protection v6.41 by Safenet"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { A1 [4] 55 8B [3] 85 C0 74 ?? 85 ED 75 ?? A1 [4] 50 55 FF 15 [4] 8B 0D [4] 55 51 FF 15 [4] 85 C0 74 ?? 8B 15 [4] 52 FF 15 [4] 6A 00 6A 00 68 [4] E8 [4] B8 01 00 00 00 5D C2 0C 00 }

	condition:
		$a0 at pe.entry_point
}
