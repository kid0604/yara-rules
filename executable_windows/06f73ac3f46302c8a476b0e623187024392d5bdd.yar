import "pe"

rule HKTL_NET_GUID_Csharp_Loader_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/NYAN-x-CAT/Csharp-Loader"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "5fd7f9fc-0618-4dde-a6a0-9faefe96c8a1" ascii wide
		$typelibguid0up = "5FD7F9FC-0618-4DDE-A6A0-9FAEFE96C8A1" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
