import "pe"

rule SLVc0deProtectorv11SLV
{
	meta:
		author = "malware-lu"
		description = "Yara rule for SLVc0deProtectorv11SLV malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 00 00 00 00 58 C6 00 EB C6 40 01 08 FF E0 E9 4C }
		$a1 = { E8 01 00 00 00 A0 5D EB 01 69 81 ED 5F 1A 40 00 8D 85 92 1A 40 00 F3 8D 95 83 1A 40 00 8B C0 8B D2 2B C2 83 E8 05 89 42 01 E8 FB FF FF FF 69 83 C4 08 E8 06 00 00 00 69 E8 F2 FF FF FF F3 B9 05 00 00 00 51 8D B5 BF 1A 40 00 8B FE B9 58 15 00 00 AC 32 C1 F6 }

	condition:
		$a0 at pe.entry_point or $a1
}
