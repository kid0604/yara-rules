import "pe"

rule MALWARE_Win_VBS_DLAgent01
{
	meta:
		author = "ditekSHen"
		description = "Detects VBS MSHTA downloader"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "llehS.tpircsW" ascii
		$s2 = ".Run" ascii
		$s3 = "mshta http" ascii nocase
		$s4 = "StrReverse" ascii

	condition:
		all of them
}
