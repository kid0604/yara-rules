import "pe"

rule Safe20_alt_1
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern in PE files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 83 EC 10 53 56 57 E8 C4 01 00 }

	condition:
		$a0
}
