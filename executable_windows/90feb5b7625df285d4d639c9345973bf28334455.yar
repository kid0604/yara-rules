rule HKTL_NET_GUID_BYTAGE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/KNIF/BYTAGE"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "8e46ba56-e877-4dec-be1e-394cb1b5b9de" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
