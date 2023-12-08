rule HKTL_NET_GUID_SharpEDRChecker
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/PwnDexter/SharpEDRChecker"
		author = "Arnim Rupp"
		date = "2020-12-18"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "bdfee233-3fed-42e5-aa64-492eb2ac7047" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
