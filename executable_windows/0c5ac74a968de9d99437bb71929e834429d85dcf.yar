import "pe"

rule EXECryptorv153
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of the EXECryptorv153 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 B8 00 00 00 00 [2] 00 31 C0 89 41 14 89 41 18 80 A1 C1 00 00 00 FE C3 31 C0 64 FF 30 64 89 20 CC C3 }

	condition:
		$a0
}
