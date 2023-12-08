rule HKTL_NET_GUID_UrbanBishopLocal
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/slyd0g/UrbanBishopLocal"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "88b8515e-a0e8-4208-a9a0-34b01d7ba533" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
