import "pe"

rule HKTL_NET_GUID_WhiteListEvasion_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/khr0x40sh/WhiteListEvasion"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "858386df-4656-4a1e-94b7-47f6aa555658" ascii wide
		$typelibguid0up = "858386DF-4656-4A1E-94B7-47F6AA555658" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
