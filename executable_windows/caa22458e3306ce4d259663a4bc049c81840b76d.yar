rule HKTL_NET_GUID_AllTheThings
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/johnjohnsp1/AllTheThings"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "0547ff40-5255-42a2-beb7-2ff0dbf7d3ba" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
