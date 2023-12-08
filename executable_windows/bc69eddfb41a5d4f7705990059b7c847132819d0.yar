rule HKTL_NET_GUID_Manager
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/TheWover/Manager"
		author = "Arnim Rupp"
		date = "2021-01-21"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "dda73ee9-0f41-4c09-9cad-8215abd60b33" ascii nocase wide
		$typelibguid1 = "6a0f2422-d4d1-4b7e-84ad-56dc0fd2dfc5" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
