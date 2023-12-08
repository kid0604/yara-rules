rule EXPL_LOG_CVE_2021_26858_Exchange_Forensic_Artefacts_Mar21_1 : LOG
{
	meta:
		description = "Detects forensic artefacts found in HAFNIUM intrusions exploiting CVE-2021-26858"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
		date = "2021-03-02"
		score = 65
		modified = "2021-03-04"
		os = "windows"
		filetype = "script"

	strings:
		$xr1 = /POST (\/owa\/auth\/Current\/themes\/resources\/logon\.css|\/owa\/auth\/Current\/themes\/resources\/owafont_ja\.css|\/owa\/auth\/Current\/themes\/resources\/lgnbotl\.gif|\/owa\/auth\/Current\/themes\/resources\/owafont_ko\.css|\/owa\/auth\/Current\/themes\/resources\/SegoeUI-SemiBold\.eot|\/owa\/auth\/Current\/themes\/resources\/SegoeUI-SemiLight\.ttf|\/owa\/auth\/Current\/themes\/resources\/lgnbotl\.gif)/

	condition:
		$xr1
}
