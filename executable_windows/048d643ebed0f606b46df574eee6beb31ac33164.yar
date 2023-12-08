import "pe"

rule HKTL_NET_GUID_SharpHound3_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/BloodHoundAD/SharpHound3"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-29"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "a517a8de-5834-411d-abda-2d0e1766539c" ascii wide
		$typelibguid0up = "A517A8DE-5834-411D-ABDA-2D0E1766539C" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
