import "pe"

rule INDICATOR_EXE_Packed_ConfuserEx
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with ConfuserEx Mod"
		snort2_sid = "930016-930018"
		snort3_sid = "930005-930006"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "ConfuserEx " ascii
		$s2 = "ConfusedByAttribute" fullword ascii
		$c1 = "Confuser.Core " ascii wide
		$u1 = "Confu v" fullword ascii
		$u2 = "ConfuByAttribute" fullword ascii

	condition:
		uint16(0)==0x5a4d and ( all of ($s*) or all of ($c*) or all of ($u*))
}
