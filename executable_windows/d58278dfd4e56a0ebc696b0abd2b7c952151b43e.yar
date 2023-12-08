import "pe"

rule HKTL_NET_GUID_RexCrypter_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/syrex1013/RexCrypter"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "10cd7c1c-e56d-4b1b-80dc-e4c496c5fec5" ascii wide
		$typelibguid0up = "10CD7C1C-E56D-4B1B-80DC-E4C496C5FEC5" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
