rule HKTL_NET_GUID_SharpCall
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/jhalon/SharpCall"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "c1b0a923-0f17-4bc8-ba0f-c87aff43e799" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
