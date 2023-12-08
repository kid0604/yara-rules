import "pe"

rule HKTL_NET_GUID_EducationalRAT_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/securesean/EducationalRAT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "8a18fbcf-8cac-482d-8ab7-08a44f0e278e" ascii wide
		$typelibguid0up = "8A18FBCF-8CAC-482D-8AB7-08A44F0E278E" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
