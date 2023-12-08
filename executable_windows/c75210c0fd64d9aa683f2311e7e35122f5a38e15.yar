rule HKTL_NET_GUID_CVE_2020_1206_POC
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/ZecOps/CVE-2020-1206-POC"
		author = "Arnim Rupp"
		date = "2021-01-21"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "3523ca04-a12d-4b40-8837-1a1d28ef96de" ascii nocase wide
		$typelibguid1 = "d3a2f24a-ddc6-4548-9b3d-470e70dbcaab" ascii nocase wide
		$typelibguid2 = "fb30ee05-4a35-45f7-9a0a-829aec7e47d9" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
