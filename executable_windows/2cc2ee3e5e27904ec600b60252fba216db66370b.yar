rule HKTL_NET_GUID_SharpMove
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/0xthirteen/SharpMove"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "8bf82bbe-909c-4777-a2fc-ea7c070ff43e" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
