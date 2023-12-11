import "pe"

rule HKTL_NET_GUID_Rubeus_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/GhostPack/Rubeus"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "658c8b7f-3664-4a95-9572-a3e5871dfc06" ascii wide
		$typelibguid0up = "658C8B7F-3664-4A95-9572-A3E5871DFC06" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
