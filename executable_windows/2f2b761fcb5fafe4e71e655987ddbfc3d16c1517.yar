import "pe"

rule Escargot01byueMeat
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of Escargot malware variant 01byueMeat"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 08 28 65 73 63 30 2E 31 29 60 68 2B [3] 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 B8 5C [3] 8B 00 FF D0 50 BE 00 10 [2] B9 00 [2] 00 EB 05 49 80 34 31 40 0B C9 75 F7 58 0B C0 74 08 33 C0 C7 00 DE C0 AD 0B BE [4] E9 AC 00 00 00 8B 46 0C BB 00 00 [2] 03 C3 50 50 B8 54 [3] 8B 00 FF D0 5F 80 3F 00 74 06 C6 07 00 47 EB F5 33 FF 8B 16 0B D2 75 03 8B 56 10 03 D3 03 D7 8B 0A C7 02 00 00 00 00 0B C9 74 4B F7 C1 00 00 00 80 74 14 81 E1 FF FF 00 00 50 51 50 B8 50 }

	condition:
		$a0
}
