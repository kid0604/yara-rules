import "pe"

rule HKTL_NET_GUID_bantam_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/gellin/bantam"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "14c79bda-2ce6-424d-bd49-4f8d68630b7b" ascii wide
		$typelibguid0up = "14C79BDA-2CE6-424D-BD49-4F8D68630B7B" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
