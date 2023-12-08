import "pe"

rule HKTL_NET_GUID_Crypter_Runtime_AV_s_bypass_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/netreverse/Crypter-Runtime-AV-s-bypass"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "c25e39a9-8215-43aa-96a3-da0e9512ec18" ascii wide
		$typelibguid0up = "C25E39A9-8215-43AA-96A3-DA0E9512EC18" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
