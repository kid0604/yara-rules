import "pe"

rule DevC4992BloodshedSoftware
{
	meta:
		author = "malware-lu"
		description = "Detects Bloodshed Software Dev-C++ malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 [3] 00 E8 C8 FE FF FF 90 8D B4 26 00 00 00 00 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 [3] 00 E8 A8 FE FF FF 90 8D B4 26 00 00 00 00 55 8B 0D [3] 00 89 E5 5D FF E1 8D 74 26 00 55 8B 0D }

	condition:
		$a0 at pe.entry_point
}
