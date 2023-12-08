import "pe"

rule y0dasCrypterv11
{
	meta:
		author = "malware-lu"
		description = "Detects y0da's Crypter v1.1"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 8A 1C 40 00 B9 9E 00 00 00 8D BD 4C 23 40 00 8B F7 33 }

	condition:
		$a0 at pe.entry_point
}
