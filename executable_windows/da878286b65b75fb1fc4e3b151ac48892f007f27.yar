import "pe"

rule HKTL_NET_GUID_CVE_2020_1337_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/neofito/CVE-2020-1337"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "d9c2e3c1-e9cc-42b0-a67c-b6e1a4f962cc" ascii wide
		$typelibguid0up = "D9C2E3C1-E9CC-42B0-A67C-B6E1A4F962CC" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
