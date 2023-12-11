rule HKTL_NET_GUID_SharpMapExec
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/cube0x0/SharpMapExec"
		author = "Arnim Rupp"
		date = "2020-12-29"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "bd5220f7-e1fb-41d2-91ec-e4c50c6e9b9f" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
