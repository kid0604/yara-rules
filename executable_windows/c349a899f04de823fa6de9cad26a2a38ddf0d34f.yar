rule HKTL_NET_GUID_WindowsPlague
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/RITRedteam/WindowsPlague"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "cdf8b024-70c9-413a-ade3-846a43845e99" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
