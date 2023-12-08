rule HKTL_NET_GUID_SharpDPAPI
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/GhostPack/SharpDPAPI"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "script"

	strings:
		$typelibguid0 = "5f026c27-f8e6-4052-b231-8451c6a73838" ascii nocase wide
		$typelibguid1 = "2f00a05b-263d-4fcc-846b-da82bd684603" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
