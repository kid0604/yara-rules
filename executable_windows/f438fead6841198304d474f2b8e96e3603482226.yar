rule HKTL_NET_GUID_Stracciatella
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/mgeeky/Stracciatella"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "eaafa0ac-e464-4fc4-9713-48aa9a6716fb" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
