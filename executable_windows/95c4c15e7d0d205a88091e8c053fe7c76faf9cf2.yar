import "pe"

rule HKTL_NET_GUID_SharpRODC
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/wh0amitz/SharpRODC"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-12-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "d305f8a3-019a-4cdf-909c-069d5b483613" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
