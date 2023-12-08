import "pe"

rule HKTL_NET_GUID_SharpShot_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/tothi/SharpShot"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "057aef75-861b-4e4b-a372-cfbd8322c8e1" ascii wide
		$typelibguid0up = "057AEF75-861B-4E4B-A372-CFBD8322C8E1" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
