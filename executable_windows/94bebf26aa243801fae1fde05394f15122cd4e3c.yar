rule HKTL_NET_GUID_SharpBypassUAC
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/FatRodzianko/SharpBypassUAC"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "0d588c86-c680-4b0d-9aed-418f1bb94255" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
