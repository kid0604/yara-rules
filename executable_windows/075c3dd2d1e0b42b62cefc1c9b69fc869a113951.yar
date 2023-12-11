import "pe"

rule STProtectorV15SilentSoftware
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of STProtector v1.5 silent software"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 00 00 00 00 4B 65 52 6E 45 6C 33 32 2E 64 4C 6C 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 }

	condition:
		$a0
}
