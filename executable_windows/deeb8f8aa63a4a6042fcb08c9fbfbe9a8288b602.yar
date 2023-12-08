import "pe"

rule HKTL_NET_GUID_LethalHTA_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/codewhitesec/LethalHTA"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "784cde17-ff0f-4e43-911a-19119e89c43f" ascii wide
		$typelibguid0up = "784CDE17-FF0F-4E43-911A-19119E89C43F" ascii wide
		$typelibguid1lo = "7e2de2c0-61dc-43ab-a0ec-c27ee2172ea6" ascii wide
		$typelibguid1up = "7E2DE2C0-61DC-43AB-A0EC-C27EE2172EA6" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
