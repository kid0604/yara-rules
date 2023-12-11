import "pe"

rule HKTL_NET_GUID_neo_ConfuserEx_alt_1
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/XenocodeRCE/neo-ConfuserEx"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "e98490bb-63e5-492d-b14e-304de928f81a" ascii wide
		$typelibguid0up = "E98490BB-63E5-492D-B14E-304DE928F81A" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
