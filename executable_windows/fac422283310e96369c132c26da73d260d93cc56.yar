import "pe"

rule HKTL_NET_GUID_scout_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/jaredhaight/scout"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "d9c76e82-b848-47d4-8f22-99bf22a8ee11" ascii wide
		$typelibguid0up = "D9C76E82-B848-47D4-8F22-99BF22A8EE11" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
