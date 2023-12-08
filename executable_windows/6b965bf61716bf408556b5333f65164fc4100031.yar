rule HKTL_NET_GUID_NashaVM
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/Mrakovic-ORG/NashaVM"
		author = "Arnim Rupp"
		date = "2021-01-21"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "f9e63498-6e92-4afd-8c13-4f63a3d964c3" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
