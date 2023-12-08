import "pe"

rule eXpressorv11CGSoftLabs
{
	meta:
		author = "malware-lu"
		description = "Detects the eXpressorv11CGSoftLabs malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 15 13 00 00 E9 F0 12 00 00 E9 58 12 00 00 E9 AF 0C 00 00 E9 AE 02 00 00 E9 B4 0B 00 00 E9 E0 0C 00 00 }

	condition:
		$a0 at pe.entry_point
}
