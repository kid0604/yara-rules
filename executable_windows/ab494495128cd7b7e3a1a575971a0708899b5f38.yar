import "pe"

rule HKTL_NET_GUID_PoshSecFramework_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/PoshSec/PoshSecFramework"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "b1ac6aa0-2f1a-4696-bf4b-0e41cf2f4b6b" ascii wide
		$typelibguid0up = "B1AC6AA0-2F1A-4696-BF4B-0E41CF2F4B6B" ascii wide
		$typelibguid1lo = "78bfcfc2-ef1c-4514-bce6-934b251666d2" ascii wide
		$typelibguid1up = "78BFCFC2-EF1C-4514-BCE6-934B251666D2" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
