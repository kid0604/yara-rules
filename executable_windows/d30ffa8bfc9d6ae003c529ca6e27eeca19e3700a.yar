import "pe"

rule ASPackv10803AlexeySolodovnikov
{
	meta:
		author = "malware-lu"
		description = "Detects ASPack v1.08.03 by Alexey Solodovnikov"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 0A 4A 44 00 BB 04 4A 44 00 03 DD }
		$a1 = { 60 E8 00 00 00 00 5D 81 ED 0A 4A 44 00 BB 04 4A 44 00 03 DD 2B 9D B1 50 44 00 83 BD AC 50 44 00 00 89 9D BB 4E }
		$a2 = { 60 E8 00 00 00 00 5D [6] BB [4] 03 DD }
		$a3 = { 60 E8 00 00 00 00 5D [6] BB [4] 03 DD 2B 9D B1 50 44 00 83 BD AC 50 44 00 00 89 9D BB 4E }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point or $a3 at pe.entry_point
}
