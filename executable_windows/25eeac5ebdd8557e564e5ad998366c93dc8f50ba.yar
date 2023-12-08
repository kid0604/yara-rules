rule HKTL_NET_GUID_Grouper2
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/l0ss/Grouper2/"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "5decaea3-2610-4065-99dc-65b9b4ba6ccd" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
