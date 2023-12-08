rule HKTL_NET_GUID_Browser_ExternalC2
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/mdsecactivebreach/Browser-ExternalC2"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "10a730cd-9517-42d5-b3e3-a2383515cca9" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
