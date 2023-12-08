rule HKTL_NET_GUID_SharpHandler
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/jfmaes/SharpHandler"
		author = "Arnim Rupp"
		date = "2021-01-21"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "46e39aed-0cff-47c6-8a63-6826f147d7bd" ascii nocase wide
		$typelibguid1 = "11dc83c6-8186-4887-b228-9dc4fd281a23" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
