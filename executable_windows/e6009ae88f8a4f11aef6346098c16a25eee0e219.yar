rule HKTL_NET_GUID_scout
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/jaredhaight/scout"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "d9c76e82-b848-47d4-8f22-99bf22a8ee11" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
