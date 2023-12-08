import "pe"

rule HKTL_NET_GUID_SharpView
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/tevora-threat/SharpView"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-22"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "22a156ea-2623-45c7-8e50-e864d9fc44d3" ascii wide
		$typelibguid0up = "22A156EA-2623-45C7-8E50-E864D9FC44D3" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
