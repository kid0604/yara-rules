rule HKTL_NET_GUID_CVE_2020_0668
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/RedCursorSecurityConsulting/CVE-2020-0668"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "1b4c5ec1-2845-40fd-a173-62c450f12ea5" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
