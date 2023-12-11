rule HKTL_NET_GUID_CSharpSetThreadContext
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/djhohnstein/CSharpSetThreadContext"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "a1e28c8c-b3bd-44de-85b9-8aa7c18a714d" ascii nocase wide
		$typelibguid1 = "87c5970e-0c77-4182-afe2-3fe96f785ebb" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
