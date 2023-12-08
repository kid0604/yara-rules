rule HKTL_NET_GUID_AzureCLI_Extractor
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/0x09AL/AzureCLI-Extractor"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "a73cad74-f8d6-43e6-9a4c-b87832cdeace" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
