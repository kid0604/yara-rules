rule HKTL_NET_GUID_ShellcodeLoader
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Hzllaga/ShellcodeLoader"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "a48fe0e1-30de-46a6-985a-3f2de3c8ac96" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
