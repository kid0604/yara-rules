rule HKTL_NET_GUID_SharpBox
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/P1CKLES/SharpBox"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "616c1afb-2944-42ed-9951-bf435cadb600" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
