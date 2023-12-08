import "pe"

rule HKTL_NET_GUID_SharpCall_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/jhalon/SharpCall"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "c1b0a923-0f17-4bc8-ba0f-c87aff43e799" ascii wide
		$typelibguid0up = "C1B0A923-0F17-4BC8-BA0F-C87AFF43E799" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
