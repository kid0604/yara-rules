rule HKTL_NET_GUID_ReverseShell
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/chango77747/ReverseShell"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "980109e4-c988-47f9-b2b3-88d63fababdc" ascii nocase wide
		$typelibguid1 = "8abe8da1-457e-4933-a40d-0958c8925985" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
