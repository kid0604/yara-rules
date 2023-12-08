import "pe"

rule ExcaliburV103forgot
{
	meta:
		author = "malware-lu"
		description = "Detects the ExcaliburV103 malware variant that targets forgotten passwords"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 6A 45 E8 A3 00 00 00 68 00 00 00 00 E8 58 61 EB 39 }

	condition:
		$a0 at pe.entry_point
}
