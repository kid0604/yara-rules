import "pe"

rule HKTL_NET_GUID_Disable_Windows_Defender_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/NYAN-x-CAT/Disable-Windows-Defender"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "501e3fdc-575d-492e-90bc-703fb6280ee2" ascii wide
		$typelibguid0up = "501E3FDC-575D-492E-90BC-703FB6280EE2" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
