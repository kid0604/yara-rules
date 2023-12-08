import "pe"

rule DevCv5
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern in executable files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 89 E5 83 EC 14 6A ?? FF 15 [3] 00 [14] 00 00 00 00 }

	condition:
		$a0
}
