import "pe"

rule HKTL_NET_GUID_EvilFOCA_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/ElevenPaths/EvilFOCA"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "f26bdb4a-5846-4bec-8f52-3c39d32df495" ascii wide
		$typelibguid0up = "F26BDB4A-5846-4BEC-8F52-3C39D32DF495" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
