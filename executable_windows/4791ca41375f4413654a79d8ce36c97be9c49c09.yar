import "pe"

rule HKTL_NET_GUID_SharpRDP_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/0xthirteen/SharpRDP"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "f1df1d0f-ff86-4106-97a8-f95aaf525c54" ascii wide
		$typelibguid0up = "F1DF1D0F-FF86-4106-97A8-F95AAF525C54" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
