import "pe"

rule ASPackv212AlexeySolodovnikov
{
	meta:
		author = "malware-lu"
		description = "Detects ASPack v2.12 by Alexey Solodovnikov"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 }
		$a1 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
