import "pe"

rule PEArmor049Hying
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file, which may indicate the presence of a certain type of malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 56 52 51 53 55 E8 15 01 00 00 32 [2] 00 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
