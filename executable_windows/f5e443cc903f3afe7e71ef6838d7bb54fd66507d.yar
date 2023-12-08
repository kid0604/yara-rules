rule HKTL_NET_GUID_MiscTools
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/rasta-mouse/MiscTools"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "384e9647-28a9-4835-8fa7-2472b1acedc0" ascii nocase wide
		$typelibguid1 = "d7ec0ef5-157c-4533-bbcd-0fe070fbf8d9" ascii nocase wide
		$typelibguid2 = "10085d98-48b9-42a8-b15b-cb27a243761b" ascii nocase wide
		$typelibguid3 = "6aacd159-f4e7-4632-bad1-2ae8526a9633" ascii nocase wide
		$typelibguid4 = "49a6719e-11a8-46e6-ad7a-1db1be9fea37" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
