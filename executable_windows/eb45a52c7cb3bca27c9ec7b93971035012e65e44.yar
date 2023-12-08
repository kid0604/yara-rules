import "pe"

rule HKTL_NET_GUID_LOLBITS_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Kudaes/LOLBITS"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "29d09aa4-ea0c-47c2-973c-1d768087d527" ascii wide
		$typelibguid0up = "29D09AA4-EA0C-47C2-973C-1D768087D527" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
