import "pe"

rule HKTL_NET_GUID_RunAsUser_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/atthacks/RunAsUser"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "9dff282c-93b9-4063-bf8a-b6798371d35a" ascii wide
		$typelibguid0up = "9DFF282C-93B9-4063-BF8A-B6798371D35A" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
