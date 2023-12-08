rule HKTL_NET_GUID_PoC
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/thezdi/PoC"
		author = "Arnim Rupp"
		date = "2020-12-21"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "89f9d411-e273-41bb-8711-209fd251ca88" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
