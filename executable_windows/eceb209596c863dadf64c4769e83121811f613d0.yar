import "pe"

rule SoftDefender1xRandyLi
{
	meta:
		author = "malware-lu"
		description = "Detects SoftDefender1xRandyLi malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 74 07 75 05 19 32 67 E8 E8 74 1F 75 1D E8 68 39 44 CD 00 59 9C 50 74 0A 75 08 E8 59 C2 04 00 55 8B EC E8 F4 FF FF FF 56 57 53 78 0F 79 0D E8 34 99 47 49 34 33 EF 31 34 52 47 23 68 A2 AF 47 01 59 E8 01 00 00 00 FF 58 05 E6 01 00 00 03 C8 74 BD 75 BB E8 00 }

	condition:
		$a0 at pe.entry_point
}
