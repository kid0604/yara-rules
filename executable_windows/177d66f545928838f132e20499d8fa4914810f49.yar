import "pe"

rule NTkrnlSecureSuite01015NTkrnlSoftware
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of NTkrnlSecureSuite01015NTkrnlSoftware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 34 10 00 00 28 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [8] 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 68 [4] E8 01 00 00 00 C3 C3 }

	condition:
		$a0
}
