rule HKTL_NET_GUID_HideFromAMSI
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/0r13lc0ch4v1/HideFromAMSI"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "b91d2d44-794c-49b8-8a75-2fbec3fe3fe3" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
