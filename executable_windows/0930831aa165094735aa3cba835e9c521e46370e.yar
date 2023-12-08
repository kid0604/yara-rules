rule HKTL_NET_GUID_SharpMiniDump
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/b4rtik/SharpMiniDump"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "6ffccf81-6c3c-4d3f-b15f-35a86d0b497f" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
