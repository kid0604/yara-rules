import "pe"

rule HKTL_NET_GUID_gray_keylogger_2_alt_1
{
	meta:
		description = "Detects VB.NET red/black-team tools via typelibguid"
		reference = "https://github.com/graysuit/gray-keylogger-2"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-30"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "e94ca3ff-c0e5-4d1a-ad5e-f6ebbe365067" ascii wide
		$typelibguid0up = "E94CA3FF-C0E5-4D1A-AD5E-F6EBBE365067" ascii wide
		$typelibguid1lo = "1ed07564-b411-4626-88e5-e1cd8ecd860a" ascii wide
		$typelibguid1up = "1ED07564-B411-4626-88E5-E1CD8ECD860A" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
