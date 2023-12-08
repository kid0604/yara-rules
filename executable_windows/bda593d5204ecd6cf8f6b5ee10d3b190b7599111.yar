import "pe"

rule PocketPCMIB
{
	meta:
		author = "malware-lu"
		description = "Detects PocketPCMIB malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 FF BD 27 14 00 BF AF 18 00 A4 AF 1C 00 A5 AF 20 00 A6 AF 24 00 A7 AF [3] 0C 00 00 00 00 18 00 A4 8F 1C 00 A5 8F 20 00 A6 8F [3] 0C 24 00 A7 8F [3] 0C 25 20 40 00 14 00 BF 8F 08 00 E0 03 18 00 BD 27 ?? FF BD 27 18 00 ?? AF ?? 00 }

	condition:
		$a0 at pe.entry_point
}
