import "pe"

rule HKTL_NET_GUID_SharpShareFinder
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/mvelazc0/SharpShareFinder"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-12-19"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "64bfeb18-b65c-4a83-bde0-b54363b09b71" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
