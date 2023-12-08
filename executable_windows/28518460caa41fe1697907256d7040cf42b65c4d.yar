rule HKTL_NET_GUID_donut
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/TheWover/donut"
		author = "Arnim Rupp"
		date = "2021-01-21"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "98ca74c7-a074-434d-9772-75896e73ceaa" ascii nocase wide
		$typelibguid1 = "3c9a6b88-bed2-4ba8-964c-77ec29bf1846" ascii nocase wide
		$typelibguid2 = "4fcdf3a3-aeef-43ea-9297-0d3bde3bdad2" ascii nocase wide
		$typelibguid3 = "361c69f5-7885-4931-949a-b91eeab170e3" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
