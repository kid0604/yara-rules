rule HKTL_NET_GUID_SolarFlare
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/mubix/solarflare"
		author = "Arnim Rupp"
		date = "2020-12-15"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "ca60e49e-eee9-409b-8d1a-d19f1d27b7e4" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
