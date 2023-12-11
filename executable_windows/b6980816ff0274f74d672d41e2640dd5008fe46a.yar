rule HKTL_NET_GUID_SharpClipboard
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/slyd0g/SharpClipboard"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "97484211-4726-4129-86aa-ae01d17690be" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
