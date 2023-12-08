rule HKTL_NET_GUID_FileSearcher
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/NVISO-BE/FileSearcher"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "2c879479-5027-4ce9-aaac-084db0e6d630" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
