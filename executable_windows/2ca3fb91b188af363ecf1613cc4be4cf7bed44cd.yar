rule HKTL_NET_GUID_logger
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/xxczaki/logger"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "9e92a883-3c8b-4572-a73e-bb3e61cfdc16" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
