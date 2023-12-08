rule HKTL_NET_GUID_PSByPassCLM
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/padovah4ck/PSByPassCLM"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "script"

	strings:
		$typelibguid0 = "46034038-0113-4d75-81fd-eb3b483f2662" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
