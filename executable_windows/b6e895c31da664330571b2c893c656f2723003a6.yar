import "pe"

rule INDICATOR_EXE_Packed_NETProtectIO
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with NETProtect.IO"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "NETProtect.IO v" ascii

	condition:
		uint16(0)==0x5a4d and 1 of them
}
