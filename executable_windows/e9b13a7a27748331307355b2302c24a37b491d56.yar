import "pe"

rule HKTL_NET_GUID_ExternalC2
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/ryhanson/ExternalC2"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "7266acbb-b10d-4873-9b99-12d2043b1d4e" ascii wide
		$typelibguid0up = "7266ACBB-B10D-4873-9B99-12D2043B1D4E" ascii wide
		$typelibguid1lo = "5d9515d0-df67-40ed-a6b2-6619620ef0ef" ascii wide
		$typelibguid1up = "5D9515D0-DF67-40ED-A6B2-6619620EF0EF" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
