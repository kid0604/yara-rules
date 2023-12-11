import "pe"

rule HKTL_NET_GUID_BypassUAC_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/cnsimo/BypassUAC"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "4e7c140d-bcc4-4b15-8c11-adb4e54cc39a" ascii wide
		$typelibguid0up = "4E7C140D-BCC4-4B15-8C11-ADB4E54CC39A" ascii wide
		$typelibguid1lo = "cec553a7-1370-4bbc-9aae-b2f5dbde32b0" ascii wide
		$typelibguid1up = "CEC553A7-1370-4BBC-9AAE-B2F5DBDE32B0" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
