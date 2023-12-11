import "pe"

rule HKTL_NET_GUID_Privilege_Escalation_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Mrakovic-ORG/Privilege_Escalation"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "ed54b904-5645-4830-8e68-52fd9ecbb2eb" ascii wide
		$typelibguid0up = "ED54B904-5645-4830-8E68-52FD9ECBB2EB" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
