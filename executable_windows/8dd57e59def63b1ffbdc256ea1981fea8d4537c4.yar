import "pe"

rule HKTL_NET_GUID_SharpByeBear_alt_1
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/S3cur3Th1sSh1t/SharpByeBear"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "a6b84e35-2112-4df2-a31b-50fde4458c5e" ascii wide
		$typelibguid0up = "A6B84E35-2112-4DF2-A31B-50FDE4458C5E" ascii wide
		$typelibguid1lo = "3e82f538-6336-4fff-aeec-e774676205da" ascii wide
		$typelibguid1up = "3E82F538-6336-4FFF-AEEC-E774676205DA" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
