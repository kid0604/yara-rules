rule HKTL_NET_GUID_Gopher
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/EncodeGroup/Gopher"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "b5152683-2514-49ce-9aca-1bc43df1e234" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
