import "pe"

rule ExeLockerv10IonIce
{
	meta:
		author = "malware-lu"
		description = "Detects ExeLocker v1.0 by IonIce"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 00 00 00 00 60 8B 6C 24 20 81 ED 05 00 00 00 3E 8F 85 6C 00 00 00 3E 8F 85 68 00 00 00 3E 8F 85 64 00 00 00 3E 8F 85 60 00 00 00 3E 8F 85 5C 00 00 00 3E 8F 85 58 00 00 00 3E 8F 85 54 00 00 }

	condition:
		$a0 at pe.entry_point
}
