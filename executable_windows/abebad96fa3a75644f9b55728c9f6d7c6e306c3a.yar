rule HKTL_NET_GUID_SharpC2
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/SharpC2/SharpC2"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "62b9ee4f-1436-4098-9bc1-dd61b42d8b81" ascii nocase wide
		$typelibguid1 = "d2f17a91-eb2d-4373-90bf-a26e46c68f76" ascii nocase wide
		$typelibguid2 = "a9db9fcc-7502-42cd-81ec-3cd66f511346" ascii nocase wide
		$typelibguid3 = "ca6cc2ee-75fd-4f00-b687-917fa55a4fae" ascii nocase wide
		$typelibguid4 = "a1167b68-446b-4c0c-a8b8-2a7278b67511" ascii nocase wide
		$typelibguid5 = "4d8c2a88-1da5-4abe-8995-6606473d7cf1" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
