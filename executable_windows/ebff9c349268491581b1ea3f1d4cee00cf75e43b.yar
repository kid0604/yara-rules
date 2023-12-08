rule HKTL_NET_GUID_MemoryMapper
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/jasondrawdy/MemoryMapper"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "b9fbf3ac-05d8-4cd5-9694-b224d4e6c0ea" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
