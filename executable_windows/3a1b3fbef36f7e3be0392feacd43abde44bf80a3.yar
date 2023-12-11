rule HKTL_NET_GUID_Povlsomware
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/povlteksttv/Povlsomware"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "fe0d5aa7-538f-42f6-9ece-b141560f7781" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
