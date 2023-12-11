rule HKTL_NET_GUID_RedSharp
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/padovah4ck/RedSharp"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "30b2e0cf-34dd-4614-a5ca-6578fb684aea" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
