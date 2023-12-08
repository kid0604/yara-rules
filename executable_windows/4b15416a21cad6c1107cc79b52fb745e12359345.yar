rule HKTL_NET_GUID_HTTPSBeaconShell
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/limbenjamin/HTTPSBeaconShell"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "aca853dc-9e74-4175-8170-e85372d5f2a9" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
