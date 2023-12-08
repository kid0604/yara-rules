import "pe"

rule ASPackv211cAlexeySolodovnikov
{
	meta:
		author = "malware-lu"
		description = "Detects ASPack v2.11c by Alexey Solodovnikov"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 E9 59 04 00 00 }

	condition:
		$a0 at pe.entry_point
}
