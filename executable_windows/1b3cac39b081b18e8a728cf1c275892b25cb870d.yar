import "pe"

rule HKTL_NET_GUID_Browser_ExternalC2_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/mdsecactivebreach/Browser-ExternalC2"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "10a730cd-9517-42d5-b3e3-a2383515cca9" ascii wide
		$typelibguid0up = "10A730CD-9517-42D5-B3E3-A2383515CCA9" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
