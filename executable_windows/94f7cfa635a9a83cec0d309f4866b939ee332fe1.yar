rule HKTL_NET_GUID_SharpSvc
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/jnqpblc/SharpSvc"
		author = "Arnim Rupp"
		date = "2021-01-21"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "52856b03-5acd-45e0-828e-13ccb16942d1" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
