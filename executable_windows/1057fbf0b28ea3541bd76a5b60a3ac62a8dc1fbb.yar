import "pe"

rule INDICATOR_EXE_Packed_NoobyProtect
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with NoopyProtect"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "NoobyProtect SE" ascii

	condition:
		uint16(0)==0x5a4d and all of them or for any i in (0..pe.number_of_sections) : ((pe.sections[i].name=="SE"))
}
