import "pe"

rule HKTL_NET_GUID_StormKitty_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/LimerBoy/StormKitty"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "a16abbb4-985b-4db2-a80c-21268b26c73d" ascii wide
		$typelibguid0up = "A16ABBB4-985B-4DB2-A80C-21268B26C73D" ascii wide
		$typelibguid1lo = "98075331-1f86-48c8-ae29-29da39a8f98b" ascii wide
		$typelibguid1up = "98075331-1F86-48C8-AE29-29DA39A8F98B" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
