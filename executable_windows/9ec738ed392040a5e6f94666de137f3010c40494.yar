import "pe"

rule HKTL_NET_GUID_SharpSvc_alt_1
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/jnqpblc/SharpSvc"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "52856b03-5acd-45e0-828e-13ccb16942d1" ascii wide
		$typelibguid0up = "52856B03-5ACD-45E0-828E-13CCB16942D1" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
