rule HKTL_NET_GUID_ESC
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/NetSPI/ESC"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "06260ce5-61f4-4b81-ad83-7d01c3b37921" ascii nocase wide
		$typelibguid1 = "87fc7ede-4dae-4f00-ac77-9c40803e8248" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
