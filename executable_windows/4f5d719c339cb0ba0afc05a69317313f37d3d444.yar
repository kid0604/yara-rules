import "pe"

rule ExeShieldCryptor13RCTomCommander
{
	meta:
		author = "malware-lu"
		description = "Detects ExeShield Cryptor 1.3 RC Tom Commander malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 8C 21 40 00 B9 51 2D 40 00 81 E9 E6 21 40 00 8B D5 81 C2 E6 21 40 00 8D 3A 8B F7 33 C0 EB 04 90 EB 01 C2 AC }

	condition:
		$a0 at pe.entry_point
}
