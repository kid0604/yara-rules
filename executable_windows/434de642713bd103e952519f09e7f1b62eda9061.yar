import "pe"

rule PackmanV10BrandonLaCombe
{
	meta:
		author = "malware-lu"
		description = "Detects PackmanV10 malware based on the entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 5B 8D 5B C6 01 1B 8B 13 8D 73 14 6A 08 59 01 16 AD 49 75 FA }

	condition:
		$a0 at pe.entry_point
}
