import "pe"

rule MALWARE_Win_FatDuke
{
	meta:
		author = "ditekSHen"
		description = "Detects FatDuke"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\\\?\\Volume" fullword ascii
		$s2 = "WINHTTP_AUTOPROXY_OPTIONS@@PAUWINHTTP_PROXY_INFO@@" ascii
		$s3 = "WINHTTP_CURRENT_USER_IE_PROXY_CONFIG@@" ascii
		$s4 = "Cannot write a Cannot find the too long string mber of records Log malfunction! Cannot create ain an invalid ra Internal sync iright function iWaitForSingleObjffsets" ascii
		$pattern = "()$^.*+?[]|\\-{},:=!" ascii
		$b64 = "eyJjb25maWdfaWQiOi" wide

	condition:
		uint16(0)==0x5a4d and (3 of ($s*) or ($b64 and 2 of them ) or (#pattern>3 and 2 of them ))
}
