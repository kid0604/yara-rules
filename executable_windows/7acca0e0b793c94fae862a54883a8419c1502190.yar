import "pe"

rule PassLock2000v10EngMoonlightSoftware
{
	meta:
		author = "malware-lu"
		description = "Detects PassLock2000v10EngMoonlightSoftware malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 53 56 57 BB 00 50 40 00 66 2E F7 05 34 20 40 00 04 00 0F 85 98 00 00 00 E8 1F 01 00 00 C7 43 60 01 00 00 00 8D 83 E4 01 00 00 50 FF 15 F0 61 40 00 83 EC 44 C7 04 24 44 00 00 00 C7 44 24 2C 00 00 00 00 54 FF 15 E8 61 40 00 B8 0A 00 00 00 F7 44 24 }

	condition:
		$a0 at pe.entry_point
}
