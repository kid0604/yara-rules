import "pe"

rule HKTL_NET_GUID_ShellcodeLoader_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Hzllaga/ShellcodeLoader"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "a48fe0e1-30de-46a6-985a-3f2de3c8ac96" ascii wide
		$typelibguid0up = "A48FE0E1-30DE-46A6-985A-3F2DE3C8AC96" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
