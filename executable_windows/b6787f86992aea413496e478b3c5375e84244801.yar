rule HKTL_NET_GUID_Tokenvator
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/0xbadjuju/Tokenvator"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "4b2b3bd4-d28f-44cc-96b3-4a2f64213109" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
