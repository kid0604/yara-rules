import "pe"

rule ThinstallEmbedded2609Jitit
{
	meta:
		author = "malware-lu"
		description = "Detects ThinstallEmbedded2609Jitit malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 00 00 00 00 58 BB AD 19 00 00 2B C3 50 68 [4] 68 B0 1C 00 00 68 80 00 00 00 E8 35 FF FF FF E9 99 FF FF FF 00 }

	condition:
		$a0 at pe.entry_point
}
