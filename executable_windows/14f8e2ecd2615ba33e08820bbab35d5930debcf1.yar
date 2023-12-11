rule HKTL_NET_GUID_StandIn
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/FuzzySecurity/StandIn"
		author = "Arnim Rupp"
		date = "2020-12-21"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "01c142ba-7af1-48d6-b185-81147a2f7db7" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
