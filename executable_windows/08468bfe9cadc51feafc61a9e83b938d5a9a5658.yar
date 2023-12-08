rule HKTL_NET_GUID_WhiteListEvasion
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/khr0x40sh/WhiteListEvasion"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "858386df-4656-4a1e-94b7-47f6aa555658" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
