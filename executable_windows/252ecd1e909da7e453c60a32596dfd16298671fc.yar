import "pe"

rule HKTL_NET_GUID_FileSearcher_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/NVISO-BE/FileSearcher"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "2c879479-5027-4ce9-aaac-084db0e6d630" ascii wide
		$typelibguid0up = "2C879479-5027-4CE9-AAAC-084DB0E6D630" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
