import "pe"

rule ObsidiumV12XObsidiumSoftware
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting ObsidiumV12 by Obsidium Software"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 0E 00 00 00 33 C0 8B 54 24 0C 83 82 B8 00 00 00 0D C3 64 67 FF 36 00 00 64 67 89 26 00 00 50 33 C0 8B 00 C3 E9 FA 00 00 00 E8 D5 FF FF FF 58 64 67 8F 06 00 00 83 C4 04 E8 2B 13 00 00 }

	condition:
		$a0 at pe.entry_point
}
