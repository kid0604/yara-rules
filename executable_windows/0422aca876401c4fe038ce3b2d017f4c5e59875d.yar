import "pe"

rule HKTL_NET_GUID_HideFromAMSI_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/0r13lc0ch4v1/HideFromAMSI"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "b91d2d44-794c-49b8-8a75-2fbec3fe3fe3" ascii wide
		$typelibguid0up = "B91D2D44-794C-49B8-8A75-2FBEC3FE3FE3" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
