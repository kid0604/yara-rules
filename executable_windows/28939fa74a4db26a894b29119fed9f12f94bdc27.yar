import "pe"

rule RLPackV10betaap0x
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of RLPackV10betaap0x malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 8D 64 24 04 8B 6C 24 FC 8D B5 4C 02 00 00 8D 9D 13 01 00 00 33 FF EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB }

	condition:
		$a0 at pe.entry_point
}
