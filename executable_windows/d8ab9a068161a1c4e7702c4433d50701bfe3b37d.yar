rule HKTL_NET_GUID_SharpExcel4_DCOM
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/rvrsh3ll/SharpExcel4-DCOM"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "68b83ce5-bbd9-4ee3-b1cc-5e9223fab52b" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
