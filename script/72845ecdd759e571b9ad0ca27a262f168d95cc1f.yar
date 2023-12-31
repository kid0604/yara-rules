rule EXPL_CVE_2021_31166_Accept_Encoding_May21_1
{
	meta:
		description = "Detects malformed Accept-Encoding header field as used in code exploiting CVE-2021-31166"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/0vercl0k/CVE-2021-31166"
		date = "2021-05-21"
		score = 70
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$xr1 = /[Aa]ccept\-[Ee]ncoding: [a-z\-]{1,16},([a-z\-\s]{1,16},|)*[\s]{1,20},/

	condition:
		1 of them
}
