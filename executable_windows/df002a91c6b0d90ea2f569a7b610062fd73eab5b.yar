import "pe"

rule HKTL_NET_GUID_SharpWitness_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/rasta-mouse/SharpWitness"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "b9f6ec34-4ccc-4247-bcef-c1daab9b4469" ascii wide
		$typelibguid0up = "B9F6EC34-4CCC-4247-BCEF-C1DAAB9B4469" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
