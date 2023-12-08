rule HKTL_NET_GUID_RexCrypter
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/syrex1013/RexCrypter"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "10cd7c1c-e56d-4b1b-80dc-e4c496c5fec5" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
