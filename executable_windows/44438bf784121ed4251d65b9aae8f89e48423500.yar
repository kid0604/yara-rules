import "pe"

rule HKTL_NET_GUID_SharpBypassUAC_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/FatRodzianko/SharpBypassUAC"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "0d588c86-c680-4b0d-9aed-418f1bb94255" ascii wide
		$typelibguid0up = "0D588C86-C680-4B0D-9AED-418F1BB94255" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
