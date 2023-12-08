import "pe"

rule AlexProtectorv04beta1byAlex
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting AlexProtectorv04beta1byAlex malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 01 00 00 00 C7 83 C4 04 33 C9 E8 01 00 00 00 68 83 C4 04 E8 01 00 00 00 68 83 C4 04 B9 ?? 00 00 00 E8 01 00 00 00 68 83 C4 04 E8 00 00 00 00 E8 01 00 00 00 C7 83 C4 04 8B 2C 24 83 C4 04 E8 01 00 00 00 A9 83 C4 04 81 ED 3C 13 40 00 E8 01 00 00 00 68 }

	condition:
		$a0
}
