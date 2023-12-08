rule HKTL_NET_GUID_SharpLoginPrompt
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/shantanu561993/SharpLoginPrompt"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "c12e69cd-78a0-4960-af7e-88cbd794af97" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
