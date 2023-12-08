import "pe"

rule HKTL_NET_GUID_Change_Lockscreen_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/nccgroup/Change-Lockscreen"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "78642ab3-eaa6-4e9c-a934-e7b0638bc1cc" ascii wide
		$typelibguid0up = "78642AB3-EAA6-4E9C-A934-E7B0638BC1CC" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
