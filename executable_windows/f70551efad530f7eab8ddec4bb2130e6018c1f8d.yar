rule HKTL_NET_GUID_nopowershell
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/bitsadmin/nopowershell"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "555ad0ac-1fdb-4016-8257-170a74cb2f55" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
