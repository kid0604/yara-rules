rule HKTL_NET_GUID_SharpLogger
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/djhohnstein/SharpLogger"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "36e00152-e073-4da8-aa0c-375b6dd680c4" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
