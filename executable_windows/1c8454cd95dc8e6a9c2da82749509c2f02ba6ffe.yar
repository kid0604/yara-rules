import "pe"

rule HKTL_NET_GUID_njCrypter_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/0xPh0enix/njCrypter"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "8a87b003-4b43-467b-a509-0c8be05bf5a5" ascii wide
		$typelibguid0up = "8A87B003-4B43-467B-A509-0C8BE05BF5A5" ascii wide
		$typelibguid1lo = "80b13bff-24a5-4193-8e51-c62a414060ec" ascii wide
		$typelibguid1up = "80B13BFF-24A5-4193-8E51-C62A414060EC" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
