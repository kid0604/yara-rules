rule HKTL_NET_GUID_DInvoke_alt_1
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/TheWover/DInvoke"
		author = "Arnim Rupp"
		date = "2021-01-21"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "b77fdab5-207c-4cdb-b1aa-348505c54229" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
