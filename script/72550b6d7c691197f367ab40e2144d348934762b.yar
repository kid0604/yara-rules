rule TA18_074A_scripts
{
	meta:
		description = "Detects malware mentioned in TA18-074A"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.us-cert.gov/ncas/alerts/TA18-074A"
		date = "2018-03-16"
		modified = "2022-08-18"
		hash1 = "2f159b71183a69928ba8f26b76772ec504aefeac71021b012bd006162e133731"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "Running -s cmd /c query user on " ascii

	condition:
		filesize <600KB and 1 of them
}
