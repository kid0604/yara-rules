rule HKTL_NET_GUID_Rubeus
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/GhostPack/Rubeus"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "658c8b7f-3664-4a95-9572-a3e5871dfc06" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
