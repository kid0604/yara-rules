rule HKTL_NET_GUID_Marauder
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/maraudershell/Marauder"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "fff0a9a3-dfd4-402b-a251-6046d765ad78" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
