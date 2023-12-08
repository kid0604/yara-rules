import "pe"

rule HKTL_NET_GUID_CVE_2020_0668_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/RedCursorSecurityConsulting/CVE-2020-0668"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "1b4c5ec1-2845-40fd-a173-62c450f12ea5" ascii wide
		$typelibguid0up = "1B4C5EC1-2845-40FD-A173-62C450F12EA5" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
