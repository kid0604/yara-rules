import "pe"

rule HKTL_NET_GUID_SharpHide_alt_1
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/outflanknl/SharpHide"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "443d8cbf-899c-4c22-b4f6-b7ac202d4e37" ascii wide
		$typelibguid0up = "443D8CBF-899C-4C22-B4F6-B7AC202D4E37" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
