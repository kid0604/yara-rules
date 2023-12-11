import "pe"

rule DJoinv07publicRC4encryptiondrmist
{
	meta:
		author = "malware-lu"
		description = "Detects public RC4 encryption in DJoinv07 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { C6 05 [2] 40 00 00 C6 05 [2] 40 00 00 [8] 00 [4] 00 [5] 00 }

	condition:
		$a0 at pe.entry_point
}
