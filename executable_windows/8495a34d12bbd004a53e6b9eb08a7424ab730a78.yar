import "pe"

rule ASPackv10801AlexeySolodovnikov
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of ASPack v1.08.01 by Alexey Solodovnikov"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 [3] 44 00 BB 10 ?? 44 00 03 DD 2B 9D }
		$a1 = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 [3] 44 ?? BB 10 ?? 44 ?? 03 DD 2B 9D }
		$a2 = { 60 EB ?? 5D EB ?? FF [5] E9 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point
}
