rule HKTL_NET_GUID_LOLBITS
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Kudaes/LOLBITS"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "29d09aa4-ea0c-47c2-973c-1d768087d527" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
