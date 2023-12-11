rule HKTL_NET_GUID_CloneVault
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/mdsecactivebreach/CloneVault"
		author = "Arnim Rupp"
		date = "2021-01-21"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "0a344f52-6780-4d10-9a4a-cb9439f9d3de" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
