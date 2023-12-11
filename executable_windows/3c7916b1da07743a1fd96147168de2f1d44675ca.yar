import "pe"

rule ObsidiumV1350ObsidiumSoftware
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting ObsidiumV1350ObsidiumSoftware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 03 [3] E8 [4] EB 02 [2] EB 04 [4] 8B 54 24 0C EB 04 [4] 83 82 B8 00 00 00 20 EB 03 [3] 33 C0 EB 01 ?? C3 EB 02 [2] EB 03 [3] 64 67 FF 36 00 00 EB 03 [3] 64 67 89 26 00 00 EB 01 ?? EB 04 [4] 50 EB 04 [4] 33 C0 EB 04 [4] 8B 00 EB 03 [3] C3 EB 02 [2] E9 FA 00 00 00 EB 01 ?? E8 [4] EB 01 ?? EB 02 [2] 58 EB 04 [4] EB 02 [2] 64 67 8F 06 00 00 EB 02 [2] 83 C4 04 EB 01 ?? E8 }

	condition:
		$a0 at pe.entry_point
}
