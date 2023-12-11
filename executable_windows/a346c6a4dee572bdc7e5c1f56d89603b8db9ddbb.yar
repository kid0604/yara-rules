rule HKTL_NET_GUID_Lime_Miner
{
	meta:
		description = "Detects VB.NET red/black-team tools via typelibguid"
		reference = "https://github.com/NYAN-x-CAT/Lime-Miner"
		author = "Arnim Rupp"
		date = "2020-12-30"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "13958fb9-dfc1-4e2c-8a8d-a5e68abdbc66" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
