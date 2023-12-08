rule HKTL_NET_GUID_EvilWMIProvider
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/sunnyc7/EvilWMIProvider"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "a4020626-f1ec-4012-8b17-a2c8a0204a4b" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
