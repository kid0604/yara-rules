rule HKTL_NET_GUID_SHAPESHIFTER
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/matterpreter/SHAPESHIFTER"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "a3ddfcaa-66e7-44fd-ad48-9d80d1651228" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
