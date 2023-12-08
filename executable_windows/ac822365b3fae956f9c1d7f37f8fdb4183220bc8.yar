import "pe"

rule HKTL_NET_GUID_Manager_alt_1
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/TheWover/Manager"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "dda73ee9-0f41-4c09-9cad-8215abd60b33" ascii wide
		$typelibguid0up = "DDA73EE9-0F41-4C09-9CAD-8215ABD60B33" ascii wide
		$typelibguid1lo = "6a0f2422-d4d1-4b7e-84ad-56dc0fd2dfc5" ascii wide
		$typelibguid1up = "6A0F2422-D4D1-4B7E-84AD-56DC0FD2DFC5" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
