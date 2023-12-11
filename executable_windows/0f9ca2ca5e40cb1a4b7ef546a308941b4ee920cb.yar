rule HKTL_NET_GUID_SharpShares
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/djhohnstein/SharpShares/"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "fe9fdde5-3f38-4f14-8c64-c3328c215cf2" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
