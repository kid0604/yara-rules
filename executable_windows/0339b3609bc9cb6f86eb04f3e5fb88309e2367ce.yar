rule HKTL_NET_GUID_SharpChisel
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/shantanu561993/SharpChisel"
		author = "Arnim Rupp"
		date = "2021-01-21"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "f5f21e2d-eb7e-4146-a7e1-371fd08d6762" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
