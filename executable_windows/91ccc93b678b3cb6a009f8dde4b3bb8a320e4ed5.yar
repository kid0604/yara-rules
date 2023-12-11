rule HKTL_NET_GUID_Minidump
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/3xpl01tc0d3r/Minidump"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "15c241aa-e73c-4b38-9489-9a344ac268a3" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
