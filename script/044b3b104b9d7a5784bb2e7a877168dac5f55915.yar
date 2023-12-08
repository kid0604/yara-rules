rule HKTL_NET_GUID_OffensivePowerShellTasking
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/leechristensen/OffensivePowerShellTasking"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "script"

	strings:
		$typelibguid0 = "d432c332-3b48-4d06-bedb-462e264e6688" ascii nocase wide
		$typelibguid1 = "5796276f-1c7a-4d7b-a089-550a8c19d0e8" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
