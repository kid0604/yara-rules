rule HKTL_NET_GUID_CinaRAT
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/wearelegal/CinaRAT"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "8586f5b1-2ef4-4f35-bd45-c6206fdc0ebc" ascii nocase wide
		$typelibguid1 = "fe184ab5-f153-4179-9bf5-50523987cf1f" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
