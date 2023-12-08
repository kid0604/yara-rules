rule HKTL_NET_GUID_Sharp_WMIExec
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/checkymander/Sharp-WMIExec"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "0a63b0a1-7d1a-4b84-81c3-bbbfe9913029" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
