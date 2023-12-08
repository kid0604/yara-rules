rule HKTL_NET_GUID_ShellGen
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/jasondrawdy/ShellGen"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "c6894882-d29d-4ae1-aeb7-7d0a9b915013" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
