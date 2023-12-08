rule HKTL_NET_GUID_CVE_2019_1253
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/padovah4ck/CVE-2019-1253"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "584964c1-f983-498d-8370-23e27fdd0399" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
