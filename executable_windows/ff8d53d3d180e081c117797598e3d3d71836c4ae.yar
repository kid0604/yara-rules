import "pe"

rule Petite21
{
	meta:
		author = "malware-lu"
		description = "Detects the Petite21 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 8B D8 }

	condition:
		$a0
}
