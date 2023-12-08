import "pe"

rule ASPackv102bAlexeySolodovnikov
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of ASPack v1.02b by Alexey Solodovnikov"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 96 78 43 00 B8 90 78 43 00 03 C5 }
		$a1 = { 60 E8 [4] 5D 81 ED 96 78 43 ?? B8 90 78 43 ?? 03 C5 2B 85 7D 7C 43 ?? 89 85 89 7C 43 ?? 80 BD 74 7C 43 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
