import "pe"

rule Petite14
{
	meta:
		author = "malware-lu"
		description = "Detects the Petite14 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 66 9C 60 50 8B D8 03 00 68 54 BC 00 00 6A 00 FF 50 14 8B CC }

	condition:
		$a0
}
