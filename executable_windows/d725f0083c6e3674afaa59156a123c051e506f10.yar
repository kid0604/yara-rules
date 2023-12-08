import "pe"

rule ASPackv21AlexeySolodovnikov
{
	meta:
		author = "malware-lu"
		description = "Detects files packed with ASPack v2.1 by Alexey Solodovnikov"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 72 05 00 00 EB 33 87 DB 90 00 }

	condition:
		$a0 at pe.entry_point
}
