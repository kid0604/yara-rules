import "pe"

rule HKTL_NET_GUID_Dropless_Malware_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/NYAN-x-CAT/Dropless-Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "23b739f7-2355-491e-a7cd-a8485d39d6d6" ascii wide
		$typelibguid0up = "23B739F7-2355-491E-A7CD-A8485D39D6D6" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
