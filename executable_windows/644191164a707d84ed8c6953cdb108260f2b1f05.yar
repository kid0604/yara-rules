rule HKTL_NET_GUID_Fenrir
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/nccgroup/Fenrir"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "aecec195-f143-4d02-b946-df0e1433bd2e" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
