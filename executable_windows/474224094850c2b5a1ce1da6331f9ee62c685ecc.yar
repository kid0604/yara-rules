import "pe"

rule PolyCryptorbySMTVersionv3v4
{
	meta:
		author = "malware-lu"
		description = "Detects PolyCryptor ransomware version 3 and 4"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB ?? 28 50 6F 6C 79 53 63 72 79 70 74 20 [3] 20 62 79 20 53 4D 54 29 }

	condition:
		$a0 at pe.entry_point
}
