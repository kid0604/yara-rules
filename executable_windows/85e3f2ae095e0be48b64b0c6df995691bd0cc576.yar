rule HKTL_NET_GUID_sharpwmi
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/QAX-A-Team/sharpwmi"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "bb357d38-6dc1-4f20-a54c-d664bd20677e" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
