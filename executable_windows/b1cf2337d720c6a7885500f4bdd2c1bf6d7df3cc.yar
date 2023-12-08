rule HKTL_NET_GUID_Watson
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/rasta-mouse/Watson"
		author = "Arnim Rupp"
		date = "2020-12-21"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "49ad5f38-9e37-4967-9e84-fe19c7434ed7" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
