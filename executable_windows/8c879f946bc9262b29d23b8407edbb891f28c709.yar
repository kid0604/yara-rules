import "pe"

rule ASPackv2000AlexeySolodovnikov
{
	meta:
		author = "malware-lu"
		description = "Detects files packed with ASPack v2.00 by Alexey Solodovnikov"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 70 05 00 00 EB 4C }

	condition:
		$a0 at pe.entry_point
}
