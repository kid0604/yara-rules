import "pe"

rule HKTL_NET_GUID_PowerOPS_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/fdiskyou/PowerOPS"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-21"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "2a3c5921-7442-42c3-8cb9-24f21d0b2414" ascii wide
		$typelibguid0up = "2A3C5921-7442-42C3-8CB9-24F21D0B2414" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
