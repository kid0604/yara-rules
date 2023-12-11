import "pe"

rule HKTL_NET_GUID_SHAPESHIFTER_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/matterpreter/SHAPESHIFTER"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "a3ddfcaa-66e7-44fd-ad48-9d80d1651228" ascii wide
		$typelibguid0up = "A3DDFCAA-66E7-44FD-AD48-9D80D1651228" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
