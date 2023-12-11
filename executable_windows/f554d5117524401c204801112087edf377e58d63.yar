rule HKTL_NET_GUID_memscan
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/nccgroup/memscan"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "79462f87-8418-4834-9356-8c11e44ce189" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
