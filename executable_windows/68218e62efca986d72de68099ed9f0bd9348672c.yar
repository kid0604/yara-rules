import "pe"

rule xPEP03xxIkUg
{
	meta:
		author = "malware-lu"
		description = "Detects a specific entry point in PE files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 53 56 51 52 57 E8 16 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
