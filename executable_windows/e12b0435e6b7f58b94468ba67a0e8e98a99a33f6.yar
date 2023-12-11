import "pe"

rule HKTL_NET_GUID_SharpSniper_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/HunnicCyber/SharpSniper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-29"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "c8bb840c-04ce-4b60-a734-faf15abf7b18" ascii wide
		$typelibguid0up = "C8BB840C-04CE-4B60-A734-FAF15ABF7B18" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
