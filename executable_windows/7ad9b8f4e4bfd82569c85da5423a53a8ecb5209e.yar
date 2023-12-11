import "pe"

rule Shrinker33
{
	meta:
		author = "malware-lu"
		description = "Detects the Shrinker33 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 00 00 55 8B EC 56 57 75 65 68 00 01 00 00 E8 }

	condition:
		$a0
}
