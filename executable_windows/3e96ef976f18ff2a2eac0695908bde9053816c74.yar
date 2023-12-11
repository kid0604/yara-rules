rule HKTL_NET_GUID_SharpBlock
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/CCob/SharpBlock"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "3cf25e04-27e4-4d19-945e-dadc37c81152" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
