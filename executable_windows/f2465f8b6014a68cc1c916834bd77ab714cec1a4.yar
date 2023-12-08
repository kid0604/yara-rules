rule HKTL_NET_GUID_DLL_Injection
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/ihack4falafel/DLL-Injection"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "3d7e1433-f81a-428a-934f-7cc7fcf1149d" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
