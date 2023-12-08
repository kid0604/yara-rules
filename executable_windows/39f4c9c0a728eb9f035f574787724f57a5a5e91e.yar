import "pe"

rule DevCv4
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern in a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 89 E5 83 EC 08 83 C4 F4 6A ?? A1 [3] 00 FF D0 E8 ?? FF FF FF }

	condition:
		$a0
}
