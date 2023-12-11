import "pe"

rule HKTL_NET_GUID_SharPermission_alt_1
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/mitchmoser/SharPermission"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "84d2b661-3267-49c8-9f51-8f72f21aea47" ascii wide
		$typelibguid0up = "84D2B661-3267-49C8-9F51-8F72F21AEA47" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
