import "pe"

rule FreeJoiner152Stubengine16GlOFF
{
	meta:
		author = "malware-lu"
		description = "Detects FreeJoiner152Stubengine16GlOFF malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 46 FD FF FF 50 E8 0C 00 00 00 FF 25 08 20 40 00 FF 25 0C 20 40 00 FF 25 10 20 40 00 FF 25 14 20 40 00 FF 25 18 20 40 00 FF 25 1C 20 40 00 FF 25 20 20 40 00 FF 25 24 20 40 00 FF 25 28 20 40 00 FF 25 00 20 40 00 }

	condition:
		$a0 at pe.entry_point
}
