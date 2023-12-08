import "pe"

rule INDICATOR_EXE_Packed_Nate
{
	meta:
		author = "ditekSHen"
		description = "Detects executables built or packed with Nate packer"
		snort2_sid = "930034-930036"
		snort3_sid = "930012"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "@.nate0" fullword ascii
		$s2 = "`.nate1" fullword ascii

	condition:
		uint16(0)==0x5a4d and 1 of them or for any i in (0..pe.number_of_sections) : ((pe.sections[i].name==".nate0" or pe.sections[i].name==".nate1"))
}
