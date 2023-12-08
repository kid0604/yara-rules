import "pe"

rule INDICATOR_EXE_Packed_ConfuserExMod_Trinity
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with ConfuserEx Mod Trinity Protector"
		snort2_sid = "930025-930030"
		snort3_sid = "930009-930010"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Trinity0-protecor|" ascii
		$s2 = "#TrinityProtector" fullword ascii
		$s3 = /Trinity\d-protector\|/ ascii

	condition:
		uint16(0)==0x5a4d and 1 of them
}
