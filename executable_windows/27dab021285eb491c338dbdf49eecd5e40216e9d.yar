import "pe"

rule HKTL_NET_GUID_BlockEtw_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Soledge/BlockEtw"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-29"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "daedf7b3-8262-4892-adc4-425dd5f85bca" ascii wide
		$typelibguid0up = "DAEDF7B3-8262-4892-ADC4-425DD5F85BCA" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
