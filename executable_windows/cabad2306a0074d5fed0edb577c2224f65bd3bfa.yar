rule HKTL_NET_GUID_BrowserPass
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/jabiel/BrowserPass"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "3cb59871-0dce-453b-857a-2d1e515b0b66" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
