import "pe"

rule HKTL_NET_GUID_Sharp_SMBExec_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/checkymander/Sharp-SMBExec"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "344ee55a-4e32-46f2-a003-69ad52b55945" ascii wide
		$typelibguid0up = "344EE55A-4E32-46F2-A003-69AD52B55945" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
