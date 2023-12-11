import "pe"

rule HKTL_NET_GUID_Stealth_Kid_RAT_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/ctsecurity/Stealth-Kid-RAT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "bf43cd33-c259-4711-8a0e-1a5c6c13811d" ascii wide
		$typelibguid0up = "BF43CD33-C259-4711-8A0E-1A5C6C13811D" ascii wide
		$typelibguid1lo = "e5b9df9b-a9e4-4754-8731-efc4e2667d88" ascii wide
		$typelibguid1up = "E5B9DF9B-A9E4-4754-8731-EFC4E2667D88" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
