rule EXPL_macOS_Switcharoo_Indicator_Dec22
{
	meta:
		description = "Detects indicators found after exploitations of CVE-2022-46689"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/zhuowei/MacDirtyCowDemo"
		date = "2022-12-19"
		score = 65
		os = "macos"
		filetype = "script"

	strings:
		$x1 = "auth       sufficient     pam_permit.so" ascii

	condition:
		filesize <1KB and $x1
}
