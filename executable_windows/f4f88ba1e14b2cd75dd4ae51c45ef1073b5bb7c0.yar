rule HKTL_NET_GUID_EducationalRAT
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/securesean/EducationalRAT"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "8a18fbcf-8cac-482d-8ab7-08a44f0e278e" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
