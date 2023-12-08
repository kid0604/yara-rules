import "pe"

rule HKTL_NET_GUID_Group3r
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/Group3r/Group3r.git"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2022-11-21"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "868a6c76-c903-4a94-96fd-a2c6ba75691c" ascii wide
		$typelibguid0up = "868A6C76-C903-4A94-96FD-A2C6BA75691C" ascii wide
		$typelibguid1lo = "caa7ab97-f83b-432c-8f9c-c5f1530f59f7" ascii wide
		$typelibguid1up = "CAA7AB97-F83B-432C-8F9C-C5F1530F59F7" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
