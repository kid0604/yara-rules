rule HKTL_NET_GUID_Quasar
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/quasar/Quasar"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "cfda6d2e-8ab3-4349-b89a-33e1f0dab32b" ascii nocase wide
		$typelibguid1 = "c7c363ba-e5b6-4e18-9224-39bc8da73172" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
