import "pe"

rule HKTL_NET_GUID_SolarFlare_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/mubix/solarflare"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-15"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "ca60e49e-eee9-409b-8d1a-d19f1d27b7e4" ascii wide
		$typelibguid0up = "CA60E49E-EEE9-409B-8D1A-D19F1D27B7E4" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
