import "pe"

rule HKTL_NET_GUID_SharpSQLPwn
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/lefayjey/SharpSQLPwn.git"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2022-11-21"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "c442ea6a-9aa1-4d9c-9c9d-7560a327089c" ascii wide
		$typelibguid0up = "C442EA6A-9AA1-4D9C-9C9D-7560A327089C" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
