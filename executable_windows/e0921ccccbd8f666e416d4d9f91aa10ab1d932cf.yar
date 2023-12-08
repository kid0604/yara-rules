rule HKTL_NET_GUID_NoMSBuild
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/rvrsh3ll/NoMSBuild"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "034a7b9f-18df-45da-b870-0e1cef500215" ascii nocase wide
		$typelibguid1 = "59b449d7-c1e8-4f47-80b8-7375178961db" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
