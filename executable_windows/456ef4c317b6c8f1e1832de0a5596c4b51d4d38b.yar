import "pe"

rule UnnamedScrambler13Bp0ke
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of UnnamedScrambler13Bp0ke malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC B9 08 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 98 56 00 10 E8 48 EB FF FF 33 C0 55 68 AC 5D 00 10 64 FF 30 64 89 20 6A 00 68 BC 5D 00 10 68 C4 5D 00 10 6A 00 E8 23 EC FF FF E8 C6 CE FF FF 6A 00 68 BC 5D 00 10 68 [4] 6A 00 E8 0B EC FF FF E8 F2 F4 FF FF B8 08 BC 00 10 33 C9 BA 04 01 00 00 E8 C1 D2 FF FF 6A 00 68 BC 5D 00 10 68 E4 5D 00 10 6A 00 E8 E2 EB FF FF 68 04 01 00 00 68 08 BC 00 10 6A 00 FF 15 68 77 00 10 6A 00 68 BC 5D 00 10 68 FC 5D 00 10 6A 00 E8 BD EB FF FF BA 10 5E 00 10 B8 70 77 00 10 E8 CA F3 FF FF 85 C0 0F 84 F7 05 00 00 BA 74 77 00 10 8B 0D 70 77 00 10 E8 FE CD FF FF 6A 00 }

	condition:
		$a0 at pe.entry_point
}
