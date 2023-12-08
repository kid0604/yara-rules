rule HKTL_NET_GUID_ADSearch
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/tomcarver16/ADSearch"
		author = "Arnim Rupp"
		date = "2021-01-21"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "4da5f1b7-8936-4413-91f7-57d6e072b4a7" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
