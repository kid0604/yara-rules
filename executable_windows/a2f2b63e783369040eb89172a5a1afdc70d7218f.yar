rule HKTL_NET_GUID_RegistryStrikesBack
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/mdsecactivebreach/RegistryStrikesBack"
		author = "Arnim Rupp"
		date = "2021-01-21"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "90ebd469-d780-4431-9bd8-014b00057665" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
