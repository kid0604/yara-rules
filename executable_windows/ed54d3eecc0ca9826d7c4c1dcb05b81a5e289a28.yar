import "pe"

rule INDICATOR_EXE_Packed_eXPressor
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with eXPressor"
		snort2_sid = "930043-930048"
		snort3_sid = "930015-930016"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "eXPressor_InstanceChecker_" fullword ascii
		$s2 = "This application was packed with an Unregistered version of eXPressor" ascii
		$s3 = ", please visit www.cgsoftlabs.ro" ascii
		$s4 = /eXPr-v\.\d+\.\d+/ ascii

	condition:
		uint16(0)==0x5a4d and 2 of them or for any i in (0..pe.number_of_sections) : ((pe.sections[i].name contains ".ex_cod"))
}
