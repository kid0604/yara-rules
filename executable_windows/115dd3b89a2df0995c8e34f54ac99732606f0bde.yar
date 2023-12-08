import "pe"

rule HKTL_NET_GUID_azure_password_harvesting_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/guardicore/azure_password_harvesting"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-21"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "7ad1ff2d-32ac-4c54-b615-9bb164160dac" ascii wide
		$typelibguid0up = "7AD1FF2D-32AC-4C54-B615-9BB164160DAC" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
