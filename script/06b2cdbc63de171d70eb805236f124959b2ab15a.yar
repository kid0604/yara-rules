rule HKTL_NET_GUID_UnmanagedPowerShell
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/leechristensen/UnmanagedPowerShell"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "script"

	strings:
		$typelibguid0 = "dfc4eebb-7384-4db5-9bad-257203029bd9" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
