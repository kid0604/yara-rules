import "pe"

rule HKTL_NET_GUID_SharpMapExec_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/cube0x0/SharpMapExec"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-29"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "bd5220f7-e1fb-41d2-91ec-e4c50c6e9b9f" ascii wide
		$typelibguid0up = "BD5220F7-E1FB-41D2-91EC-E4C50C6E9B9F" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
