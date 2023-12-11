import "pe"

rule HKTL_NET_GUID_AtYourService_alt_1
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/mitchmoser/AtYourService"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "bc72386f-8b4c-44de-99b7-b06a8de3ce3f" ascii wide
		$typelibguid0up = "BC72386F-8B4C-44DE-99B7-B06A8DE3CE3F" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
