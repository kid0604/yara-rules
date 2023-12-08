import "pe"

rule HKTL_NET_GUID_Carbuncle_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/checkymander/Carbuncle"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "3f239b73-88ae-413b-b8c8-c01a35a0d92e" ascii wide
		$typelibguid0up = "3F239B73-88AE-413B-B8C8-C01A35A0D92E" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
