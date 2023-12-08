import "pe"

rule ASPackv105bAlexeySolodovnikov
{
	meta:
		author = "malware-lu"
		description = "Detects ASPack v1.05b by Alexey Solodovnikov"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 [4] 5D 81 ED CE 3A 44 ?? B8 C8 3A 44 ?? 03 C5 2B 85 B5 3E 44 ?? 89 85 C1 3E 44 ?? 80 BD AC 3E 44 }

	condition:
		$a0 at pe.entry_point
}
