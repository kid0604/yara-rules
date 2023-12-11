import "pe"

rule ASPackv101bAlexeySolodovnikov
{
	meta:
		author = "malware-lu"
		description = "Detects ASPack v1.01b by Alexey Solodovnikov"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 [4] 5D 81 ED D2 2A 44 ?? B8 CC 2A 44 ?? 03 C5 2B 85 A5 2E 44 ?? 89 85 B1 2E 44 ?? 80 BD 9C 2E 44 }

	condition:
		$a0 at pe.entry_point
}
