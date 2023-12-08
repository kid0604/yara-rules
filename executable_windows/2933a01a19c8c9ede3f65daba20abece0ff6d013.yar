import "pe"

rule HKTL_NET_GUID_ShellGen_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/jasondrawdy/ShellGen"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "c6894882-d29d-4ae1-aeb7-7d0a9b915013" ascii wide
		$typelibguid0up = "C6894882-D29D-4AE1-AEB7-7D0A9B915013" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
