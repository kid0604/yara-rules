rule HKTL_NET_GUID_Telegra_Csharp_C2
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/sf197/Telegra_Csharp_C2"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "1d79fabc-2ba2-4604-a4b6-045027340c85" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
