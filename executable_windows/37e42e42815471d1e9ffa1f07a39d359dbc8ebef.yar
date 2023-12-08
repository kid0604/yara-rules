rule HKTL_NET_GUID_SharpStat
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Raikia/SharpStat"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "ffc5c721-49c8-448d-8ff4-2e3a7b7cc383" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
