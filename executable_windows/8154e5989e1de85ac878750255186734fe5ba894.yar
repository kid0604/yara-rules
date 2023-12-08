import "pe"

rule SentinelSuperProAutomaticProtectionv640Safenet
{
	meta:
		author = "malware-lu"
		description = "Detects Sentinel SuperPro automatic protection v6.40 SafeNet"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 68 [4] 6A 01 6A 00 FF 15 [4] A3 [4] FF 15 [4] 33 C9 3D B7 00 00 00 A1 [4] 0F 94 C1 85 C0 89 0D [4] 0F 85 [4] 55 56 C7 05 [4] 01 00 00 00 FF 15 [4] 01 05 [4] FF 15 }

	condition:
		$a0 at pe.entry_point
}
