import "pe"

rule HKTL_NET_GUID_SpoolSample
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/leechristensen/SpoolSample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-22"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "640c36b4-f417-4d85-b031-83a9d23c140b" ascii wide
		$typelibguid0up = "640C36B4-F417-4D85-B031-83A9D23C140B" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
