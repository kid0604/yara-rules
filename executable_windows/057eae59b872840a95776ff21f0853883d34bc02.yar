import "pe"

rule HKTL_NET_GUID_RestrictedAdmin
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/GhostPack/RestrictedAdmin"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-18"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "79f11fc0-abff-4e1f-b07c-5d65653d8952" ascii wide
		$typelibguid0up = "79F11FC0-ABFF-4E1F-B07C-5D65653D8952" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
