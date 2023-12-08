rule HKTL_NET_GUID_CasperStager
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/ustayready/CasperStager"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "c653a9f2-0939-43c8-9b93-fed5e2e4c7e6" ascii nocase wide
		$typelibguid1 = "48dfc55e-6ae5-4a36-abef-14bc09d7510b" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
