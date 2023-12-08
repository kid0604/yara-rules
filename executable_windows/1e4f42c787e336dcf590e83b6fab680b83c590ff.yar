import "pe"

rule HKTL_NET_GUID_iSpyKeylogger_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/mwsrc/iSpyKeylogger"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "ccc0a386-c4ce-42ef-aaea-b2af7eff4ad8" ascii wide
		$typelibguid0up = "CCC0A386-C4CE-42EF-AAEA-B2AF7EFF4AD8" ascii wide
		$typelibguid1lo = "816b8b90-2975-46d3-aac9-3c45b26437fa" ascii wide
		$typelibguid1up = "816B8B90-2975-46D3-AAC9-3C45B26437FA" ascii wide
		$typelibguid2lo = "279b5533-d3ac-438f-ba89-3fe9de2da263" ascii wide
		$typelibguid2up = "279B5533-D3AC-438F-BA89-3FE9DE2DA263" ascii wide
		$typelibguid3lo = "88d3dc02-2853-4bf0-b6dc-ad31f5135d26" ascii wide
		$typelibguid3up = "88D3DC02-2853-4BF0-B6DC-AD31F5135D26" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
