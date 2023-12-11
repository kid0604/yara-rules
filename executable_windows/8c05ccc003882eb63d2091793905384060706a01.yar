import "pe"

rule ASPackv10804AlexeySolodovnikov
{
	meta:
		author = "malware-lu"
		description = "Detects ASPack v1.08.04 by Alexey Solodovnikov"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 41 06 00 00 EB 41 }

	condition:
		$a0 at pe.entry_point
}
