import "pe"

rule HKTL_NET_GUID_CloneVault_alt_1
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/mdsecactivebreach/CloneVault"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "0a344f52-6780-4d10-9a4a-cb9439f9d3de" ascii wide
		$typelibguid0up = "0A344F52-6780-4D10-9A4A-CB9439F9D3DE" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
