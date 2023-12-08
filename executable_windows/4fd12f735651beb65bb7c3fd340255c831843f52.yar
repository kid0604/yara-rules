import "pe"

rule HKTL_NET_GUID_DeviceGuardBypasses_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/tyranid/DeviceGuardBypasses"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "f318466d-d310-49ad-a967-67efbba29898" ascii wide
		$typelibguid0up = "F318466D-D310-49AD-A967-67EFBBA29898" ascii wide
		$typelibguid1lo = "3705800f-1424-465b-937d-586e3a622a4f" ascii wide
		$typelibguid1up = "3705800F-1424-465B-937D-586E3A622A4F" ascii wide
		$typelibguid2lo = "256607c2-4126-4272-a2fa-a1ffc0a734f0" ascii wide
		$typelibguid2up = "256607C2-4126-4272-A2FA-A1FFC0A734F0" ascii wide
		$typelibguid3lo = "4e6ceea1-f266-401c-b832-f91432d46f42" ascii wide
		$typelibguid3up = "4E6CEEA1-F266-401C-B832-F91432D46F42" ascii wide
		$typelibguid4lo = "1e6e9b03-dd5f-4047-b386-af7a7904f884" ascii wide
		$typelibguid4up = "1E6E9B03-DD5F-4047-B386-AF7A7904F884" ascii wide
		$typelibguid5lo = "d85e3601-0421-4efa-a479-f3370c0498fd" ascii wide
		$typelibguid5up = "D85E3601-0421-4EFA-A479-F3370C0498FD" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
