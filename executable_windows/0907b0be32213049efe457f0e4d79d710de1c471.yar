rule HKTL_NET_GUID_Driver_Template
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/FuzzySecurity/Driver-Template"
		author = "Arnim Rupp"
		date = "2021-01-21"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "bdb79ad6-639f-4dc2-8b8a-cd9107da3d69" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
