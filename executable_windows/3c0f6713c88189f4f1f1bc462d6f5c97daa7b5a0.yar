rule HKTL_NET_GUID_OSSFileTool
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/B1eed/OSSFileTool"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "207aca5d-dcd6-41fb-8465-58b39efcde8b" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
