import "pe"

rule INDICATOR_EXE_Packed_PS2EXE
{
	meta:
		author = "ditekSHen"
		description = "Detects executables built or packed with PS2EXE"
		snort2_sid = "930004-930006"
		snort3_sid = "930001"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "PS2EXE" fullword ascii
		$s2 = "PS2EXEApp" fullword ascii
		$s3 = "PS2EXEHost" fullword ascii
		$s4 = "PS2EXEHostUI" fullword ascii
		$s5 = "PS2EXEHostRawUI" fullword ascii

	condition:
		uint16(0)==0x5a4d and 1 of them
}
