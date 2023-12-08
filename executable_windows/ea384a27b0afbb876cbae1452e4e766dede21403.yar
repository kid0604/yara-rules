rule HKTL_NET_GUID_NoAmci
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/med0x2e/NoAmci"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "352e80ec-72a5-4aa6-aabe-4f9a20393e8e" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
