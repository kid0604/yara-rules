import "pe"

rule ABCCryptor10byZloY
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of the ABCCryptor 1.0 malware by ZloY"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 68 FF 64 24 F0 68 58 58 58 58 90 FF D4 50 8B 40 F2 05 B0 95 F6 95 0F 85 01 81 BB FF 68 [4] BF 00 [3] B9 00 [3] 80 37 ?? 47 39 CF 75 F8 [54] BF 00 [3] B9 00 [3] 80 37 ?? 47 39 CF 75 F8 }

	condition:
		$a0
}
