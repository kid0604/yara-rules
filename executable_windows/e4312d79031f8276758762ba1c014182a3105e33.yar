import "pe"

rule Petite13
{
	meta:
		author = "malware-lu"
		description = "Detects the Petite13 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 66 9C 60 50 8D 88 00 F0 00 00 8D 90 04 16 00 00 8B DC 8B E1 }

	condition:
		$a0
}
