import "pe"

rule HKTL_NET_GUID_ShellCodeRunner_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/antman1p/ShellCodeRunner"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "634874b7-bf85-400c-82f0-7f3b4659549a" ascii wide
		$typelibguid0up = "634874B7-BF85-400C-82F0-7F3B4659549A" ascii wide
		$typelibguid1lo = "2f9c3053-077f-45f2-b207-87c3c7b8f054" ascii wide
		$typelibguid1up = "2F9C3053-077F-45F2-B207-87C3C7B8F054" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
