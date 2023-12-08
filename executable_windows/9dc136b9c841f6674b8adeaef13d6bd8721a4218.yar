import "pe"

rule HKTL_NET_GUID_CsharpAmsiBypass_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/WayneJLee/CsharpAmsiBypass"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "4ab3b95d-373c-4197-8ee3-fe0fa66ca122" ascii wide
		$typelibguid0up = "4AB3B95D-373C-4197-8EE3-FE0FA66CA122" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
