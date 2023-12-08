import "pe"

rule HKTL_NET_GUID_IIS_backdoor_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/WBGlIl/IIS_backdoor"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "3fda4aa9-6fc1-473f-9048-7edc058c4f65" ascii wide
		$typelibguid0up = "3FDA4AA9-6FC1-473F-9048-7EDC058C4F65" ascii wide
		$typelibguid1lo = "73ca4159-5d13-4a27-8965-d50c41ab203c" ascii wide
		$typelibguid1up = "73CA4159-5D13-4A27-8965-D50C41AB203C" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
