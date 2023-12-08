rule EXPL_LOG_CVE_2021_27065_Exchange_Forensic_Artefacts_Mar21_1 : LOG
{
	meta:
		description = "Detects forensic artefacts found in HAFNIUM intrusions exploiting CVE-2021-27065"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
		date = "2021-03-02"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "S:CMD=Set-OabVirtualDirectory.ExternalUrl='" ascii wide fullword

	condition:
		1 of them
}
