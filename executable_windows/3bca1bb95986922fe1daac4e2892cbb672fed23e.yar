import "pe"

rule VIRUSIWormBagle
{
	meta:
		author = "malware-lu"
		description = "Detects the VIRUSIWormBagle malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 6A 00 E8 95 01 00 00 E8 9F E6 FF FF 83 3D 03 50 40 00 00 75 14 68 C8 AF 00 00 E8 01 E1 FF FF 05 88 13 00 00 A3 03 50 40 00 68 5C 57 40 00 68 F6 30 40 00 FF 35 03 50 40 00 E8 B0 EA FF FF E8 3A FC FF FF 83 3D 54 57 40 00 00 74 05 E8 F3 FA FF FF 68 E8 03 00 }

	condition:
		$a0
}
