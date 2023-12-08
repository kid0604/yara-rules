import "pe"

rule HKTL_NET_GUID_Nuages_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/p3nt4/Nuages"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-29"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "e9e80ac7-4c13-45bd-9bde-ca89aadf1294" ascii wide
		$typelibguid0up = "E9E80AC7-4C13-45BD-9BDE-CA89AADF1294" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
