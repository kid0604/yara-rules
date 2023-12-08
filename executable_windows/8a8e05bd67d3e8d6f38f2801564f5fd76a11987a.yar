import "pe"

rule HKTL_NET_GUID_SharpBox_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/P1CKLES/SharpBox"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "616c1afb-2944-42ed-9951-bf435cadb600" ascii wide
		$typelibguid0up = "616C1AFB-2944-42ED-9951-BF435CADB600" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
