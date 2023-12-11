import "pe"

rule ASPackv108xAlexeySolodovnikov
{
	meta:
		author = "malware-lu"
		description = "Detects ASPack v1.08x Alexey Solodovnikov packed files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 EB 03 5D FF E5 E8 F8 FF FF FF 81 ED 1B 6A 44 00 BB 10 6A 44 00 03 DD 2B 9D 2A }

	condition:
		$a0 at pe.entry_point
}
