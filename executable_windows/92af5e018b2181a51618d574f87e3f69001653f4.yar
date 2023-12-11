import "pe"

rule RLPv073betaap0x
{
	meta:
		author = "malware-lu"
		description = "Detects RLPv073betaap0x malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 8B DD E8 00 00 00 00 5D 95 32 C0 95 89 9D 80 00 00 00 B8 42 31 40 00 BB 41 30 40 00 2B C3 03 C5 33 D2 8A 10 40 B9 [2] 00 00 8B F9 30 10 8A 10 40 49 75 F8 64 EF 86 3D 30 00 00 0F B9 FF 4B 89 52 5C 4C BD 77 C2 0C CE 88 4E 2D E8 00 00 00 5D 0D DB 5E 56 }

	condition:
		$a0
}
