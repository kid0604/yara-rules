import "pe"

rule INDICATOR_EXE_Packed_Yano
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with Yano Obfuscator"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "YanoAttribute" fullword ascii
		$s2 = "StripAfterObfuscation" fullword ascii

	condition:
		uint16(0)==0x5a4d and all of them
}
