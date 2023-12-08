rule HKTL_NET_GUID_C_Sharp_R_A_T_Client
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/AdvancedHacker101/C-Sharp-R.A.T-Client"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "6d9e8852-e86c-4e36-9cb4-b3c3853ed6b8" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
