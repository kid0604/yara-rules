rule HKTL_NET_GUID_SharpPack
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Lexus89/SharpPack"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid1 = "b59c7741-d522-4a41-bf4d-9badddebb84a" ascii nocase wide
		$typelibguid2 = "fd6bdf7a-fef4-4b28-9027-5bf750f08048" ascii nocase wide
		$typelibguid3 = "6dd22880-dac5-4b4d-9c91-8c35cc7b8180" ascii nocase wide
		$typelibguid5 = "f3037587-1a3b-41f1-aa71-b026efdb2a82" ascii nocase wide
		$typelibguid6 = "41a90a6a-f9ed-4a2f-8448-d544ec1fd753" ascii nocase wide
		$typelibguid7 = "3787435b-8352-4bd8-a1c6-e5a1b73921f4" ascii nocase wide
		$typelibguid8 = "fdd654f5-5c54-4d93-bf8e-faf11b00e3e9" ascii nocase wide
		$typelibguid9 = "aec32155-d589-4150-8fe7-2900df4554c8" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
