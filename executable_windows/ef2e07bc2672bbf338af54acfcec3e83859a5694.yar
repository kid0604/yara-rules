import "pe"

rule FreeJoinerSmallbuild035GlOFF
{
	meta:
		author = "malware-lu"
		description = "Detects FreeJoinerSmallbuild035GlOFF malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 51 33 CB 86 C9 59 E8 9E FD FF FF 66 87 DB 6A 00 E8 0C 00 00 00 FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }

	condition:
		$a0 at pe.entry_point
}
