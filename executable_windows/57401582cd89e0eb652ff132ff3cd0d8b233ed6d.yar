import "pe"

rule HKTL_NET_GUID_SharpStat_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Raikia/SharpStat"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "ffc5c721-49c8-448d-8ff4-2e3a7b7cc383" ascii wide
		$typelibguid0up = "FFC5C721-49C8-448D-8FF4-2E3A7B7CC383" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
