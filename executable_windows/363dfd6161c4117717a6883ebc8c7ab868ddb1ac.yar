import "pe"

rule HKTL_NET_GUID_SharpAllowedToAct_alt_1
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/pkb1s/SharpAllowedToAct"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "dac5448a-4ad1-490a-846a-18e4e3e0cf9a" ascii wide
		$typelibguid0up = "DAC5448A-4AD1-490A-846A-18E4E3E0CF9A" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
