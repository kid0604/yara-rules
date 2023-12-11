rule HKTL_NET_GUID_SharpScribbles
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/V1V1/SharpScribbles"
		author = "Arnim Rupp"
		date = "2021-01-21"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "aa61a166-31ef-429d-a971-ca654cd18c3b" ascii nocase wide
		$typelibguid1 = "0dc1b824-c6e7-4881-8788-35aecb34d227" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
