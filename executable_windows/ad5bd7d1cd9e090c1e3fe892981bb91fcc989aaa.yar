import "pe"

rule INDICATOR_EXE_Packed_AspireCrypt
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with AspireCrypt"
		snort2_sid = "930013-930015"
		snort3_sid = "930004"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "AspireCrypt" fullword ascii
		$s2 = "aspirecrypt.net" ascii
		$s3 = "protected by AspireCrypt" ascii

	condition:
		uint16(0)==0x5a4d and 1 of them
}
