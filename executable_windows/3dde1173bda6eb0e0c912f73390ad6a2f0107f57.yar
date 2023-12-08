import "pe"

rule EXECryptor224StrongbitSoftCompleteDevelopmenth3
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of the EXECryptor 2.24 StrongbitSoft Complete Developmenth3 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 }

	condition:
		$a0
}
