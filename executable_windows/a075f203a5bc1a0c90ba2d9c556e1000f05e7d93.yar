import "pe"

rule HKTL_NET_GUID_SharpMove_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/0xthirteen/SharpMove"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "8bf82bbe-909c-4777-a2fc-ea7c070ff43e" ascii wide
		$typelibguid0up = "8BF82BBE-909C-4777-A2FC-EA7C070FF43E" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
