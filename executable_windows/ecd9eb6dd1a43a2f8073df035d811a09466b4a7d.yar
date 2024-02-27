import "pe"

rule HKTL_NET_GUID_Sharpcat
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/theart42/Sharpcat"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-11-30"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "d16fd95f-23ce-4f8d-8763-b9f5a9cdd0c3" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
