import "pe"

rule UnnamedScrambler12C12Dp0ke
{
	meta:
		author = "malware-lu"
		description = "Detects the UnnamedScrambler12C12Dp0ke malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC B9 05 00 00 00 6A 00 6A 00 49 75 F9 51 53 56 57 B8 ?? 3A [2] E8 ?? EC FF FF 33 C0 55 68 [4] 64 FF 30 64 89 20 E8 ?? D7 FF FF E8 [2] FF FF B8 20 [3] 33 C9 BA 04 01 00 00 E8 ?? DB FF FF 68 04 01 00 00 68 20 [3] 6A 00 FF 15 10 [3] BA [4] B8 14 [3] E8 [2] FF FF 85 C0 0F 84 ?? 04 00 00 BA 18 [3] 8B 0D 14 [3] E8 [2] FF FF 8B 05 88 [3] 8B D0 B8 54 [3] E8 ?? E3 FF FF B8 54 [3] E8 ?? E2 FF FF 8B D0 B8 18 [3] 8B 0D 88 [3] E8 ?? D6 FF FF FF 35 34 [3] FF 35 30 [3] FF 35 3C [3] FF 35 38 [3] 8D 55 E8 A1 88 [3] E8 ?? F0 FF FF 8B 55 E8 B9 54 }

	condition:
		$a0
}
