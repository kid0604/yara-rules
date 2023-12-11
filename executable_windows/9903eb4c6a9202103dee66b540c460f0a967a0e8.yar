rule HKTL_NET_GUID_SharpCOM
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/rvrsh3ll/SharpCOM"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "51960f7d-76fe-499f-afbd-acabd7ba50d1" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
