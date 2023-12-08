import "pe"

rule HKTL_NET_GUID_UglyEXe_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/fashionproof/UglyEXe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "233de44b-4ec1-475d-a7d6-16da48d6fc8d" ascii wide
		$typelibguid0up = "233DE44B-4EC1-475D-A7D6-16DA48D6FC8D" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
