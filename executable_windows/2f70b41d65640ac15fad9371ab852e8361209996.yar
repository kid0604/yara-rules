rule HKTL_NET_GUID_DLL_Injector
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/tmthrgd/DLL-Injector"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "4581a449-7d20-4c59-8da2-7fd830f1fd5e" ascii nocase wide
		$typelibguid1 = "05f4b238-25ce-40dc-a890-d5bbb8642ee4" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
