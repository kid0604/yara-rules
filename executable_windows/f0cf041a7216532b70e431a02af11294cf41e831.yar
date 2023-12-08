rule HKTL_NET_GUID_gray_keylogger_2
{
	meta:
		description = "Detects VB.NET red/black-team tools via typelibguid"
		reference = "https://github.com/graysuit/gray-keylogger-2"
		author = "Arnim Rupp"
		date = "2020-12-30"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "e94ca3ff-c0e5-4d1a-ad5e-f6ebbe365067" ascii nocase wide
		$typelibguid1 = "1ed07564-b411-4626-88e5-e1cd8ecd860a" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
