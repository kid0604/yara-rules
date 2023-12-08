import "pe"

rule HKTL_NET_GUID_SharpSecDump_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/G0ldenGunSec/SharpSecDump"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "e2fdd6cc-9886-456c-9021-ee2c47cf67b7" ascii wide
		$typelibguid0up = "E2FDD6CC-9886-456C-9021-EE2C47CF67B7" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
