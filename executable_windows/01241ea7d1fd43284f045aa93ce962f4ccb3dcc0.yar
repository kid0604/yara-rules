import "pe"

rule HKTL_NET_GUID_WindowsDefender_Payload_Downloader_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/notkohlrexo/WindowsDefender-Payload-Downloader"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "2f8b4d26-7620-4e11-b296-bc46eba3adfc" ascii wide
		$typelibguid0up = "2F8B4D26-7620-4E11-B296-BC46EBA3ADFC" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
