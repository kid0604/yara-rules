rule HKTL_NET_GUID_Change_Lockscreen
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/nccgroup/Change-Lockscreen"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "78642ab3-eaa6-4e9c-a934-e7b0638bc1cc" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
