rule HKTL_NET_GUID_RuralBishop
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/rasta-mouse/RuralBishop"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "fe4414d9-1d7e-4eeb-b781-d278fe7a5619" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
