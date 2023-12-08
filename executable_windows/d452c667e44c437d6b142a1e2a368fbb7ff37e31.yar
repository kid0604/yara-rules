import "pe"

rule HKTL_NET_GUID_ADFSDump_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/fireeye/ADFSDump"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "9ee27d63-6ac9-4037-860b-44e91bae7f0d" ascii wide
		$typelibguid0up = "9EE27D63-6AC9-4037-860B-44E91BAE7F0D" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
