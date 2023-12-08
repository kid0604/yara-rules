import "pe"

rule ActiveMARK5xTrymediaSystemsInc
{
	meta:
		author = "malware-lu"
		description = "Detects ActiveMARK5xTrymediaSystemsInc malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 20 2D 2D 4D 50 52 4D 4D 47 56 41 2D 2D 00 75 73 65 72 33 32 2E 64 6C 6C 00 4D 65 73 73 61 67 65 42 6F 78 41 00 54 68 69 73 20 61 70 70 6C 69 63 61 74 69 6F 6E 20 63 61 6E 6E 6F 74 20 72 75 6E 20 77 69 74 68 20 61 6E 20 61 63 74 69 76 65 20 64 65 62 75 67 }

	condition:
		$a0
}
