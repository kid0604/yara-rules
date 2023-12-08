import "pe"

rule HKTL_NET_GUID_SharpLoginPrompt_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/shantanu561993/SharpLoginPrompt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "c12e69cd-78a0-4960-af7e-88cbd794af97" ascii wide
		$typelibguid0up = "C12E69CD-78A0-4960-AF7E-88CBD794AF97" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
