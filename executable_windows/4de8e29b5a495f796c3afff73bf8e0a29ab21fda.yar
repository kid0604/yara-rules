rule HKTL_NET_GUID_UnstoppableService
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/malcomvetter/UnstoppableService"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "0c117ee5-2a21-dead-beef-8cc7f0caaa86" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
