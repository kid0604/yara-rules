import "pe"

rule HKTL_NET_GUID_SharpChisel_alt_1
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/shantanu561993/SharpChisel"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "f5f21e2d-eb7e-4146-a7e1-371fd08d6762" ascii wide
		$typelibguid0up = "F5F21E2D-EB7E-4146-A7E1-371FD08D6762" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
