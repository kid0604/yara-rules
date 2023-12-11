import "pe"

rule FreeCryptor01build001GlOFF
{
	meta:
		author = "malware-lu"
		description = "Detects FreeCryptor version 01 build 001"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 8B 04 24 40 90 83 C0 07 80 38 90 90 74 02 EB FF 68 26 [2] 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 FF E4 90 8B 04 24 64 A3 00 00 00 00 8B 64 24 08 90 83 C4 08 }

	condition:
		$a0
}
