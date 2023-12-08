import "pe"

rule HKTL_NET_GUID_BlackNET_alt_1
{
	meta:
		description = "Detects VB.NET red/black-team tools via typelibguid"
		reference = "https://github.com/BlackHacker511/BlackNET"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-30"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "c2b90883-abee-4cfa-af66-dfd93ec617a5" ascii wide
		$typelibguid0up = "C2B90883-ABEE-4CFA-AF66-DFD93EC617A5" ascii wide
		$typelibguid1lo = "8bb6f5b4-e7c7-4554-afd1-48f368774837" ascii wide
		$typelibguid1up = "8BB6F5B4-E7C7-4554-AFD1-48F368774837" ascii wide
		$typelibguid2lo = "983ae28c-91c3-4072-8cdf-698b2ff7a967" ascii wide
		$typelibguid2up = "983AE28C-91C3-4072-8CDF-698B2FF7A967" ascii wide
		$typelibguid3lo = "9ac18cdc-3711-4719-9cfb-5b5f2d51fd5a" ascii wide
		$typelibguid3up = "9AC18CDC-3711-4719-9CFB-5B5F2D51FD5A" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
