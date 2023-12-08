import "pe"

rule HKTL_NET_GUID_fakelogonscreen_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/bitsadmin/fakelogonscreen"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "d35a55bd-3189-498b-b72f-dc798172e505" ascii wide
		$typelibguid0up = "D35A55BD-3189-498B-B72F-DC798172E505" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
