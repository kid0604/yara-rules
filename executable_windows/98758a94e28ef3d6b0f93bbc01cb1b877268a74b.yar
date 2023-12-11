import "pe"

rule HKTL_NET_GUID_RuralBishop_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/rasta-mouse/RuralBishop"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "fe4414d9-1d7e-4eeb-b781-d278fe7a5619" ascii wide
		$typelibguid0up = "FE4414D9-1D7E-4EEB-B781-D278FE7A5619" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
