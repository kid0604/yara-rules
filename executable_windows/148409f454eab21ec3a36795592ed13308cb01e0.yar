import "pe"

rule HvS_APT27_HyperBro_Stage3_C2
{
	meta:
		description = "HyperBro Stage 3 C2 path and user agent detection - also tested in memory"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Marc Stroebel"
		reference = "https://www.hvs-consulting.de/en/threat-intelligence-report-emissary-panda-apt27"
		date = "2022-02-07"
		hash1 = "624e85bd669b97bc55ed5c5ea5f6082a1d4900d235a5d2e2a5683a04e36213e8"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "api/v2/ajax" ascii wide nocase
		$s2 = "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.116 Safari/537.36" ascii wide nocase

	condition:
		all of them
}
