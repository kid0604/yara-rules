rule HKTL_NET_GUID_SharpByeBear
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/S3cur3Th1sSh1t/SharpByeBear"
		author = "Arnim Rupp"
		date = "2021-01-21"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "a6b84e35-2112-4df2-a31b-50fde4458c5e" ascii nocase wide
		$typelibguid1 = "3e82f538-6336-4fff-aeec-e774676205da" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
