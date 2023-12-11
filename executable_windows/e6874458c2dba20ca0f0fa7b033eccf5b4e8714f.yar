import "pe"

rule HKTL_NET_GUID_ADSearch_alt_1
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/tomcarver16/ADSearch"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "4da5f1b7-8936-4413-91f7-57d6e072b4a7" ascii wide
		$typelibguid0up = "4DA5F1B7-8936-4413-91F7-57D6E072B4A7" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
