import "pe"

rule HKTL_NET_GUID_Naga_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/byt3bl33d3r/Naga"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "99428732-4979-47b6-a323-0bb7d6d07c95" ascii wide
		$typelibguid0up = "99428732-4979-47B6-A323-0BB7D6D07C95" ascii wide
		$typelibguid1lo = "a2c9488f-6067-4b17-8c6f-2d464e65c535" ascii wide
		$typelibguid1up = "A2C9488F-6067-4B17-8C6F-2D464E65C535" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
