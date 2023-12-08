import "pe"

rule HKTL_NET_GUID_sharpwmi_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/QAX-A-Team/sharpwmi"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "bb357d38-6dc1-4f20-a54c-d664bd20677e" ascii wide
		$typelibguid0up = "BB357D38-6DC1-4F20-A54C-D664BD20677E" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
