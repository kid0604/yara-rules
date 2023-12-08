rule HKTL_NET_GUID_azure_password_harvesting
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/guardicore/azure_password_harvesting"
		author = "Arnim Rupp"
		date = "2020-12-21"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "7ad1ff2d-32ac-4c54-b615-9bb164160dac" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
