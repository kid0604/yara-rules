import "pe"

rule HKTL_NET_GUID_RedSharp_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/padovah4ck/RedSharp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "30b2e0cf-34dd-4614-a5ca-6578fb684aea" ascii wide
		$typelibguid0up = "30B2E0CF-34DD-4614-A5CA-6578FB684AEA" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
