import "pe"

rule HKTL_NET_GUID_Aladdin
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/nettitude/Aladdin"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "b2b3adb0-1669-4b94-86cb-6dd682ddbea3" ascii wide
		$typelibguid0up = "B2B3ADB0-1669-4B94-86CB-6DD682DDBEA3" ascii wide
		$typelibguid1lo = "c47e4d64-cc7f-490e-8f09-055e009f33ba" ascii wide
		$typelibguid1up = "C47E4D64-CC7F-490E-8F09-055E009F33BA" ascii wide
		$typelibguid2lo = "32a91b0f-30cd-4c75-be79-ccbd6345de99" ascii wide
		$typelibguid2up = "32A91B0F-30CD-4C75-BE79-CCBD6345DE99" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
