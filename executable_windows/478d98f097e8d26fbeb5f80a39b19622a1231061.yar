import "pe"

rule ASPackv211dAlexeySolodovnikov
{
	meta:
		author = "malware-lu"
		description = "Detects ASPack v2.11d by Alexey Solodovnikov"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 02 00 00 00 EB 09 5D 55 }

	condition:
		$a0 at pe.entry_point
}
