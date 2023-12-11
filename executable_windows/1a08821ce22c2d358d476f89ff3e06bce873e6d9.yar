rule HKTL_NET_GUID_AV_Evasion_Tool
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/1y0n/AV_Evasion_Tool"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "1937ee16-57d7-4a5f-88f4-024244f19dc6" ascii nocase wide
		$typelibguid1 = "7898617d-08d2-4297-adfe-5edd5c1b828b" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
