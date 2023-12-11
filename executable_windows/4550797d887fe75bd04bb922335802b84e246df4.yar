import "pe"

rule HKTL_NET_GUID_TeleShadow2_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/ParsingTeam/TeleShadow2"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "42c5c356-39cf-4c07-96df-ebb0ccf78ca4" ascii wide
		$typelibguid0up = "42C5C356-39CF-4C07-96DF-EBB0CCF78CA4" ascii wide
		$typelibguid1lo = "0242b5b1-4d26-413e-8c8c-13b4ed30d510" ascii wide
		$typelibguid1up = "0242B5B1-4D26-413E-8C8C-13B4ED30D510" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
