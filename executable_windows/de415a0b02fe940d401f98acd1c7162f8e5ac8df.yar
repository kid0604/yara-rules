rule HKTL_NET_GUID_CVE_2020_1337
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/neofito/CVE-2020-1337"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "d9c2e3c1-e9cc-42b0-a67c-b6e1a4f962cc" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
