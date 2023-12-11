import "pe"

rule HKTL_NET_GUID_SharpSearch_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/djhohnstein/SharpSearch"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "98fee742-8410-4f20-8b2d-d7d789ab003d" ascii wide
		$typelibguid0up = "98FEE742-8410-4F20-8B2D-D7D789AB003D" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
