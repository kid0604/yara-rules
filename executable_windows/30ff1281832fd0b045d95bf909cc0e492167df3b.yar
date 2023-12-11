import "pe"

rule y0dasCrypterv10
{
	meta:
		author = "malware-lu"
		description = "Detects y0da's Crypter v1.0"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED E7 1A 40 00 E8 A1 00 00 00 E8 D1 00 00 00 E8 85 01 00 00 F7 85 }

	condition:
		$a0 at pe.entry_point
}
