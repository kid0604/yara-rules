rule HKTL_NET_GUID_DreamProtectorFree
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Paskowsky/DreamProtectorFree"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "f7e8a902-2378-426a-bfa5-6b14c4b40aa3" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
