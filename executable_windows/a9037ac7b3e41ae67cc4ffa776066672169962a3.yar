import "pe"

rule INDICATOR_EXE_Packed_Spices
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with 9Rays.Net Spices.Net Obfuscator."
		snort2_sid = "930001-930003"
		snort3_sid = "930000"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "9Rays.Net Spices.Net" ascii
		$s2 = "protected by 9Rays.Net Spices.Net Obfuscator" ascii

	condition:
		uint16(0)==0x5a4d and 1 of them
}
