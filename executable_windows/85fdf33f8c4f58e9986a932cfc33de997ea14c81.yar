import "pe"

rule HKTL_NET_GUID_ToxicEye_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/LimerBoy/ToxicEye"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "1bcfe538-14f4-4beb-9a3f-3f9472794902" ascii wide
		$typelibguid0up = "1BCFE538-14F4-4BEB-9A3F-3F9472794902" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
