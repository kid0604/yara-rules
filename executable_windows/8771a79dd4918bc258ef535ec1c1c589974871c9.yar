import "pe"

rule HKTL_NET_GUID_Sharp_WMIExec_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/checkymander/Sharp-WMIExec"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "0a63b0a1-7d1a-4b84-81c3-bbbfe9913029" ascii wide
		$typelibguid0up = "0A63B0A1-7D1A-4B84-81C3-BBBFE9913029" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
