import "pe"

rule HKTL_NET_GUID_AzureCLI_Extractor_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/0x09AL/AzureCLI-Extractor"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "a73cad74-f8d6-43e6-9a4c-b87832cdeace" ascii wide
		$typelibguid0up = "A73CAD74-F8D6-43E6-9A4C-B87832CDEACE" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
