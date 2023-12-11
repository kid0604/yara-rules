import "pe"

rule INDICATOR_EXE_Packed_Dotfuscator
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with Dotfuscator"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "DotfuscatorAttribute" fullword ascii

	condition:
		uint16(0)==0x5a4d and 1 of them
}
