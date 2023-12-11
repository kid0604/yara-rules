import "pe"

rule HKTL_NET_GUID_SharpDump_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/GhostPack/SharpDump"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "79c9bba3-a0ea-431c-866c-77004802d8a0" ascii wide
		$typelibguid0up = "79C9BBA3-A0EA-431C-866C-77004802D8A0" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
