import "pe"

rule MAL_APT_NK_Andariel_KaosRAT_Yamabot
{
	meta:
		author = "CISA.gov"
		description = "Detects the KaosRAT variant"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
		date = "2024-07-25"
		score = 70
		id = "cdde69cd-1b38-52f5-8552-cef2cf4ad69c"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = "/kaos/"
		$str2 = "Abstand ["
		$str3 = "] anwenden"
		$str4 = "cmVjYXB0Y2hh"
		$str5 = "/bin/sh"
		$str6 = "utilities.CIpaddress"
		$str7 = "engine.NewEgg"
		$str8 = "%s%04x%s%s%s"
		$str9 = "Y2FwdGNoYV9zZXNzaW9u"
		$str10 = "utilities.EierKochen"
		$str11 = "kandidatKaufhaus"

	condition:
		3 of them
}
