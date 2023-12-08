import "pe"

rule HKTL_NET_GUID_AddReferenceDotRedTeam_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/ceramicskate0/AddReferenceDotRedTeam"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "73c79d7e-17d4-46c9-be5a-ecef65b924e4" ascii wide
		$typelibguid0up = "73C79D7E-17D4-46C9-BE5A-ECEF65B924E4" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
