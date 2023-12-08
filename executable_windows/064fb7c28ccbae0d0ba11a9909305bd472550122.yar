rule HKTL_NET_GUID_BrowserGhost
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/QAX-A-Team/BrowserGhost"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "2133c634-4139-466e-8983-9a23ec99e01b" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
