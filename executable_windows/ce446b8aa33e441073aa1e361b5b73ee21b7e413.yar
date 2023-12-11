rule HKTL_NET_GUID_SharpHide
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/outflanknl/SharpHide"
		author = "Arnim Rupp"
		date = "2021-01-21"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "443d8cbf-899c-4c22-b4f6-b7ac202d4e37" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
