import "pe"

rule Shrinker34
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of Shrinker34 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 56 57 75 6B 68 00 01 00 00 E8 11 0B 00 00 83 C4 04 }

	condition:
		$a0
}
