import "pe"

rule HKTL_NET_GUID_SharpHandler_alt_1
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/jfmaes/SharpHandler"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "46e39aed-0cff-47c6-8a63-6826f147d7bd" ascii wide
		$typelibguid0up = "46E39AED-0CFF-47C6-8A63-6826F147D7BD" ascii wide
		$typelibguid1lo = "11dc83c6-8186-4887-b228-9dc4fd281a23" ascii wide
		$typelibguid1up = "11DC83C6-8186-4887-B228-9DC4FD281A23" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
