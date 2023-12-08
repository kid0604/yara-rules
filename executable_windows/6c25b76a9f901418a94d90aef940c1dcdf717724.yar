import "pe"

rule INDICATOR_EXE_Packed_CryptoProtector
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with CryptoProtector / CryptoObfuscator"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "CryptoObfuscator" ascii
		$s2 = "CryptoProtector [{0}]" wide
		$e1 = /[A-F0-9]{7,8}\.Crypto/ ascii

	condition:
		uint16(0)==0x5a4d and all of ($s*) or (($s1) and #e1>10) or all of them
}
