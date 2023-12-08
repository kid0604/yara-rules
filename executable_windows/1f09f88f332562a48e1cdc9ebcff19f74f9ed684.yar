import "pe"

rule ExeJoiner10Yodaf2f
{
	meta:
		author = "malware-lu"
		description = "Detects the ExeJoiner10Yodaf2f malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 68 00 10 40 00 68 04 01 00 00 E8 39 03 00 00 05 00 10 40 00 C6 00 5C 68 04 01 00 00 68 04 11 40 00 6A 00 E8 1A 03 00 00 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 68 04 11 40 00 E8 EC 02 00 00 83 F8 FF 0F 84 83 02 00 00 A3 08 12 40 00 6A 00 50 }

	condition:
		$a0 at pe.entry_point
}
