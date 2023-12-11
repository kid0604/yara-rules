rule HKTL_NET_GUID_hanzoInjection
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/P0cL4bs/hanzoInjection"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "32e22e25-b033-4d98-a0b3-3d2c3850f06c" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
