rule HKTL_NET_GUID_sitrep
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/mdsecactivebreach/sitrep"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "12963497-988f-46c0-9212-28b4b2b1831b" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
