import "pe"

rule Noodlecrypt2rsc
{
	meta:
		author = "malware-lu"
		description = "Detects Noodlecrypt2rsc malware by checking for specific bytes at the entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 01 9A E8 76 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
