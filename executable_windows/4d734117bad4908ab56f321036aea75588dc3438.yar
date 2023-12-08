rule HKTL_NET_GUID_Offensive__NET
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/mrjamiebowman/Offensive-.NET"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "11fe5fae-b7c1-484a-b162-d5578a802c9c" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
