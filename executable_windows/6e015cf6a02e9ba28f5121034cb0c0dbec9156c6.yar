import "pe"

rule HKTL_NET_GUID_StandIn_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/FuzzySecurity/StandIn"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-21"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "01c142ba-7af1-48d6-b185-81147a2f7db7" ascii wide
		$typelibguid0up = "01C142BA-7AF1-48D6-B185-81147A2F7DB7" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
