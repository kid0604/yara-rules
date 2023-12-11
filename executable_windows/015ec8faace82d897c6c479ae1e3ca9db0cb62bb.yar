rule HKTL_NET_GUID_LimeLogger
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/NYAN-x-CAT/LimeLogger"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "068d14ef-f0a1-4f9d-8e27-58b4317830c6" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
