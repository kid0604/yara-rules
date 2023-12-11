import "pe"

rule HKTL_NET_GUID_SafetyKatz_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/GhostPack/SafetyKatz"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "8347e81b-89fc-42a9-b22c-f59a6a572dec" ascii wide
		$typelibguid0up = "8347E81B-89FC-42A9-B22C-F59A6A572DEC" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
