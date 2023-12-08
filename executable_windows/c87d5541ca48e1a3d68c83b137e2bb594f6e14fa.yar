import "pe"

rule INDICATOR_EXE_Packed_Enigma
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with Enigma"
		snort2_sid = "930052-930054"
		snort3_sid = "930018"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = ".enigma0" fullword ascii
		$s2 = ".enigma1" fullword ascii
		$s3 = ".enigma2" fullword ascii
		$s4 = ".enigma3" fullword ascii

	condition:
		uint16(0)==0x5a4d and 2 of them or for any i in (0..pe.number_of_sections) : ((pe.sections[i].name==".enigma0" or pe.sections[i].name==".enigma1" or pe.sections[i].name==".enigma2" or pe.sections[i].name==".enigma3"))
}
