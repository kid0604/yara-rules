import "pe"

rule HKTL_NET_GUID_PoshC2_Misc_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/nettitude/PoshC2_Misc"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "85773eb7-b159-45fe-96cd-11bad51da6de" ascii wide
		$typelibguid0up = "85773EB7-B159-45FE-96CD-11BAD51DA6DE" ascii wide
		$typelibguid1lo = "9d32ad59-4093-420d-b45c-5fff391e990d" ascii wide
		$typelibguid1up = "9D32AD59-4093-420D-B45C-5FFF391E990D" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
