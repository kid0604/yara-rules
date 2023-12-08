import "pe"

rule CICompressv10
{
	meta:
		author = "malware-lu"
		description = "Detects CICompressv10 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 6A 04 68 00 10 00 00 FF 35 9C 14 40 00 6A 00 FF 15 38 10 40 00 A3 FC 10 40 00 97 BE 00 20 40 00 E8 71 00 00 00 3B 05 9C 14 40 00 75 61 6A 00 6A 20 6A 02 6A 00 6A 03 68 00 00 00 C0 68 94 10 40 00 FF 15 2C 10 40 00 A3 F8 10 40 00 6A 00 68 F4 10 40 00 FF 35 }

	condition:
		$a0 at pe.entry_point
}
