rule HKTL_NET_GUID_EasyNet
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/TheWover/EasyNet"
		author = "Arnim Rupp"
		date = "2021-01-21"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "3097d856-25c2-42c9-8d59-2cdad8e8ea12" ascii nocase wide
		$typelibguid1 = "ba33f716-91e0-4cf7-b9bd-b4d558f9a173" ascii nocase wide
		$typelibguid2 = "37d6dd3f-5457-4d8b-a2e1-c7b156b176e5" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
