rule HKTL_NET_GUID_Carbuncle
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/checkymander/Carbuncle"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "3f239b73-88ae-413b-b8c8-c01a35a0d92e" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
