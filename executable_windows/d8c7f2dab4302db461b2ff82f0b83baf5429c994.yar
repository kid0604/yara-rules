import "pe"

rule INDICATOR_EXE_Packed_LSD
{
	meta:
		author = "ditekSHen"
		description = "Detects executables built or packed with LSD packer"
		snort2_sid = "930058-930060"
		snort3_sid = "930021"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "This file is packed with the LSD executable packer" ascii
		$s2 = "http://lsd.dg.com" ascii
		$s3 = "&V0LSD!$" fullword ascii

	condition:
		( uint16(0)==0x5a4d or uint16(0)==0x457f) and 1 of them
}
