import "pe"

rule HKTL_NET_GUID_MemoryMapper_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/jasondrawdy/MemoryMapper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "b9fbf3ac-05d8-4cd5-9694-b224d4e6c0ea" ascii wide
		$typelibguid0up = "B9FBF3AC-05D8-4CD5-9694-B224D4E6C0EA" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
