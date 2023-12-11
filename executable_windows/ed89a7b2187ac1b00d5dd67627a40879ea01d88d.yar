rule HKTL_NET_GUID_Inception
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/two06/Inception"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "03d96b8c-efd1-44a9-8db2-0b74db5d247a" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
