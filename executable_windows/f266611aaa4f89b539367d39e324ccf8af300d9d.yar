import "pe"

rule HKTL_NET_GUID_KrbRelay
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/cube0x0/KrbRelay"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2022-11-21"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "ed839154-90d8-49db-8cdd-972d1a6b2cfd" ascii wide
		$typelibguid0up = "ED839154-90D8-49DB-8CDD-972D1A6B2CFD" ascii wide
		$typelibguid1lo = "3b47eebc-0d33-4e0b-bab5-782d2d3680af" ascii wide
		$typelibguid1up = "3B47EEBC-0D33-4E0B-BAB5-782D2D3680AF" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
