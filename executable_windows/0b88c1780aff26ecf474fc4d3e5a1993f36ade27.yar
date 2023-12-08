rule HKTL_NET_GUID_SharpCrashEventLog
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/slyd0g/SharpCrashEventLog"
		author = "Arnim Rupp"
		date = "2021-01-21"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "98cb495f-4d47-4722-b08f-cefab2282b18" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
