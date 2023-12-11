import "pe"

rule INDICATOR_EXE_Packed_Goliath
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with Goliath"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "ObfuscatedByGoliath" fullword ascii

	condition:
		uint16(0)==0x5a4d and 1 of them
}
