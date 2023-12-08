import "pe"

rule ChinaProtectdummy
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting ChinaProtectdummy malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { C3 E8 [4] B9 [4] E8 [4] FF 30 C3 B9 [4] E8 [4] FF 30 C3 B9 [4] E8 [4] FF 30 C3 B9 [4] E8 [4] FF 30 C3 56 8B [3] 6A 40 68 00 10 00 00 8D [2] 50 6A 00 E8 [4] 89 30 83 C0 04 5E C3 8B 44 [2] 56 8D [2] 68 00 40 00 00 FF 36 56 E8 [4] 68 00 80 00 00 6A 00 56 E8 [4] 5E C3 }

	condition:
		$a0
}
