import "pe"

rule HKTL_NET_GUID_SharpOxidResolver
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/S3cur3Th1sSh1t/SharpOxidResolver"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-22"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "ce59f8ff-0ecf-41e9-a1fd-1776ca0b703d" ascii wide
		$typelibguid0up = "CE59F8FF-0ECF-41E9-A1FD-1776CA0B703D" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
