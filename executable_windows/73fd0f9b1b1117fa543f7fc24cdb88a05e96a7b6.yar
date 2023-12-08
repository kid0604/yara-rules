rule HKTL_NET_GUID_BlockEtw
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Soledge/BlockEtw"
		author = "Arnim Rupp"
		date = "2020-12-29"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "daedf7b3-8262-4892-adc4-425dd5f85bca" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
