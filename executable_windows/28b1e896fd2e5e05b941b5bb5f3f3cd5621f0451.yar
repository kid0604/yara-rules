import "pe"

rule Petite12c1998IanLuck
{
	meta:
		author = "malware-lu"
		description = "Detects the Petite12c1998IanLuck malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 66 9C 60 E8 CA 00 00 00 03 00 04 00 05 00 06 00 07 00 08 00 09 00 0A 00 0B 00 0D 00 0F 00 11 00 13 00 17 00 1B 00 1F 00 23 00 2B 00 33 00 3B 00 43 00 53 00 63 00 73 00 83 00 A3 00 C3 00 E3 00 02 01 00 00 00 00 00 00 00 00 00 00 00 00 01 01 01 01 02 02 02 }

	condition:
		$a0 at pe.entry_point
}
