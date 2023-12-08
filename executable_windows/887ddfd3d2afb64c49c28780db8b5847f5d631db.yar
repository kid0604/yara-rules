import "pe"

rule INDICATOR_EXE_Packed_Fody
{
	meta:
		author = "ditekSHen"
		description = "Detects executables manipulated with Fody"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "ProcessedByFody" fullword ascii wide

	condition:
		uint16(0)==0x5a4d and all of them
}
