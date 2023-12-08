import "pe"

rule HKTL_NET_GUID_DotNetToJScript_LanguageModeBreakout_alt_1
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/FuzzySecurity/DotNetToJScript-LanguageModeBreakout"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		os = "windows"
		filetype = "script"

	strings:
		$typelibguid0lo = "deadb33f-fa94-41b5-813d-e72d8677a0cf" ascii wide
		$typelibguid0up = "DEADB33F-FA94-41B5-813D-E72D8677A0CF" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
