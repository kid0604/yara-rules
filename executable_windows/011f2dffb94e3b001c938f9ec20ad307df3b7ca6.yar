import "pe"

rule HKTL_NET_GUID_SharpWifiGrabber_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/r3nhat/SharpWifiGrabber"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-29"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "c0997698-2b73-4982-b25b-d0578d1323c2" ascii wide
		$typelibguid0up = "C0997698-2B73-4982-B25B-D0578D1323C2" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
