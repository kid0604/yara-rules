rule HKTL_NET_GUID_WindowsDefender_Payload_Downloader
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/notkohlrexo/WindowsDefender-Payload-Downloader"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "2f8b4d26-7620-4e11-b296-bc46eba3adfc" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
