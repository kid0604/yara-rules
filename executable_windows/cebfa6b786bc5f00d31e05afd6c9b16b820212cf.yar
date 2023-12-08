import "pe"

rule HKTL_NET_GUID_DesktopGrabber_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/NYAN-x-CAT/DesktopGrabber"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "e6aa0cd5-9537-47a0-8c85-1fbe284a4380" ascii wide
		$typelibguid0up = "E6AA0CD5-9537-47A0-8C85-1FBE284A4380" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
