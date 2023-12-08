rule HKTL_NET_GUID_fakelogonscreen
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/bitsadmin/fakelogonscreen"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "d35a55bd-3189-498b-b72f-dc798172e505" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
