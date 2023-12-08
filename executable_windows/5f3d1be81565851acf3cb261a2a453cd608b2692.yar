import "pe"

rule PackItBitch10archphase
{
	meta:
		author = "malware-lu"
		description = "Detects PackItBitch10archphase malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 28 [3] 35 [3] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 41 [3] 50 [3] 00 00 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 [7] 79 [3] 7D [3] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
		$a0
}
