rule HKTL_NET_GUID_DoHC2
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/SpiderLabs/DoHC2"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "9877a948-2142-4094-98de-e0fbb1bc4062" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
