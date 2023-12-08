import "pe"

rule Shrinker32
{
	meta:
		author = "malware-lu"
		description = "Detects the Shrinker32 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 56 57 75 65 68 00 01 00 00 E8 F1 E6 FF FF 83 C4 04 }

	condition:
		$a0
}
