import "pe"

rule HKTL_NET_GUID_UAC_Escaper_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/NYAN-x-CAT/UAC-Escaper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "95359279-5cfa-46f6-b400-e80542a7336a" ascii wide
		$typelibguid0up = "95359279-5CFA-46F6-B400-E80542A7336A" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
