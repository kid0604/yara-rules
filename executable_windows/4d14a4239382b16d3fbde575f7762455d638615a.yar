rule HKTL_NET_GUID_DeviceGuardBypasses
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/tyranid/DeviceGuardBypasses"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "f318466d-d310-49ad-a967-67efbba29898" ascii nocase wide
		$typelibguid1 = "3705800f-1424-465b-937d-586e3a622a4f" ascii nocase wide
		$typelibguid2 = "256607c2-4126-4272-a2fa-a1ffc0a734f0" ascii nocase wide
		$typelibguid3 = "4e6ceea1-f266-401c-b832-f91432d46f42" ascii nocase wide
		$typelibguid4 = "1e6e9b03-dd5f-4047-b386-af7a7904f884" ascii nocase wide
		$typelibguid5 = "d85e3601-0421-4efa-a479-f3370c0498fd" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
