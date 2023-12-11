rule HKTL_NET_GUID_SharpAllowedToAct
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/pkb1s/SharpAllowedToAct"
		author = "Arnim Rupp"
		date = "2021-01-21"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "dac5448a-4ad1-490a-846a-18e4e3e0cf9a" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
