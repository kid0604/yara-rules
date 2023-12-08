rule HKTL_NET_GUID_TruffleSnout
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/dsnezhkov/TruffleSnout"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "33842d77-bce3-4ee8-9ee2-9769898bb429" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
