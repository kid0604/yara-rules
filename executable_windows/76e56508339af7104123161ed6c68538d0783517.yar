import "pe"

rule FreeJoinerSmallbuild033GlOFF
{
	meta:
		author = "malware-lu"
		description = "Detects FreeJoinerSmallbuild033GlOFF malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 50 66 33 C3 66 8B C1 58 E8 AC FD FF FF 6A 00 E8 0D 00 00 00 CC FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }

	condition:
		$a0 at pe.entry_point
}
