rule HKTL_NET_GUID_UglyEXe
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/fashionproof/UglyEXe"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "233de44b-4ec1-475d-a7d6-16da48d6fc8d" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
