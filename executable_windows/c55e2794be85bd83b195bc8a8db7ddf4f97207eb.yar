import "pe"

rule NTkrnlSecureSuiteNTkrnlteam
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of NTkrnlSecureSuiteNTkrnlteam malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 34 10 00 00 28 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 41 10 00 00 50 10 00 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 }

	condition:
		$a0
}
