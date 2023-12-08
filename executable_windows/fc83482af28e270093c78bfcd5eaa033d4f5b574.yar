rule HKTL_NET_GUID_ShellCodeRunner
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/antman1p/ShellCodeRunner"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "634874b7-bf85-400c-82f0-7f3b4659549a" ascii nocase wide
		$typelibguid1 = "2f9c3053-077f-45f2-b207-87c3c7b8f054" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
