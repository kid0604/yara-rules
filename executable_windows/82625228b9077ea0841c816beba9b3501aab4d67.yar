rule HKTL_NET_GUID_SharpCompile
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/SpiderLabs/SharpCompile"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "63f81b73-ff18-4a36-b095-fdcb4776da4c" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
