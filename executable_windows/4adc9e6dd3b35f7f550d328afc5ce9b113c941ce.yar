import "pe"

rule HKTL_NET_GUID_SharpEDRChecker_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/PwnDexter/SharpEDRChecker"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-18"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "bdfee233-3fed-42e5-aa64-492eb2ac7047" ascii wide
		$typelibguid0up = "BDFEE233-3FED-42E5-AA64-492EB2AC7047" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
