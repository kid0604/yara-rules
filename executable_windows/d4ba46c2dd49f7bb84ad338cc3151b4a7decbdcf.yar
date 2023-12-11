import "pe"

rule ThinstallEmbedded26202623Jitit
{
	meta:
		author = "malware-lu"
		description = "Detects Thinstall embedded Jitit malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 00 00 00 00 58 BB AC 1E 00 00 2B C3 50 68 [4] 68 B0 21 00 00 68 C4 00 00 00 E8 C3 FE FF FF E9 99 FF FF FF 00 00 }

	condition:
		$a0 at pe.entry_point
}
