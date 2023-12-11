rule HKTL_NET_GUID_Ladon
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/k8gege/Ladon"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "c335405f-5df2-4c7d-9b53-d65adfbed412" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
