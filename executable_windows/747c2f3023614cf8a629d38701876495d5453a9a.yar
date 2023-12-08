import "pe"

rule HKTL_NET_GUID_Gopher_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/EncodeGroup/Gopher"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "b5152683-2514-49ce-9aca-1bc43df1e234" ascii wide
		$typelibguid0up = "B5152683-2514-49CE-9ACA-1BC43DF1E234" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
