rule HKTL_NET_GUID_SharpShell
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/cobbr/SharpShell"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "bdba47c5-e823-4404-91d0-7f6561279525" ascii nocase wide
		$typelibguid1 = "b84548dc-d926-4b39-8293-fa0bdef34d49" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
