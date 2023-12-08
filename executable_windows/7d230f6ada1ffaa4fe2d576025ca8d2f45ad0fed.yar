import "pe"

rule INDICATOR_EXE_Packed_ConfuserExMod_BedsProtector
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with ConfuserEx Mod Beds Protector"
		snort2_sid = "930019-930024"
		snort3_sid = "930007-930008"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Beds Protector v" ascii
		$s2 = "Beds-Protector-v" ascii

	condition:
		uint16(0)==0x5a4d and 1 of them
}
