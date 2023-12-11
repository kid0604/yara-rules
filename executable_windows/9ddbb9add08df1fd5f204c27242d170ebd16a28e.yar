import "pe"

rule HKTL_NET_GUID_Grouper2_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/l0ss/Grouper2/"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "5decaea3-2610-4065-99dc-65b9b4ba6ccd" ascii wide
		$typelibguid0up = "5DECAEA3-2610-4065-99DC-65B9B4BA6CCD" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
