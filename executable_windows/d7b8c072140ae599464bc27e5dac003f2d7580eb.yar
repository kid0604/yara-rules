import "pe"

rule AverCryptor102betaos1r1s
{
	meta:
		author = "malware-lu"
		description = "Detects AverCryptor 1.02 beta ransomware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 0C 17 40 00 8B BD 33 18 40 00 8B 8D 3B 18 40 00 B8 51 18 40 00 03 C5 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 37 18 40 00 33 C0 51 33 C9 66 B9 F7 00 66 83 F9 00 74 49 8B 57 0C 03 95 37 18 40 00 8B 85 3F 18 40 00 83 F8 02 75 06 81 C2 00 02 00 00 51 8B 4F 10 83 F8 02 75 06 81 E9 00 02 00 00 57 BF C8 00 00 00 8B F1 E8 27 00 00 00 8B C8 5F B8 51 18 40 00 03 C5 E8 24 00 00 00 59 49 EB B1 59 83 C7 28 49 EB 8A 8B 85 2F 18 40 00 89 44 24 1C 61 FF E0 56 57 4F F7 D7 23 F7 8B C6 5F 5E C3 }

	condition:
		$a0 at pe.entry_point
}
