rule HKTL_NET_GUID_p0wnedShell
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Cn33liz/p0wnedShell"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "2e9b1462-f47c-48ca-9d85-004493892381" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
