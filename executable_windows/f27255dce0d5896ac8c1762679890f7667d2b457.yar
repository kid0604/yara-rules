rule HKTL_NET_GUID_HiveJack
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Viralmaniar/HiveJack"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "e12e62fe-bea3-4989-bf04-6f76028623e3" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
