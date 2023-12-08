import "pe"

rule HvS_APT27_HyperBro_Stage3_Persistence
{
	meta:
		description = "HyperBro Stage 3 registry keys for persistence"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Marko Dorfhuber"
		reference = "https://www.hvs-consulting.de/en/threat-intelligence-report-emissary-panda-apt27"
		date = "2022-02-07"
		hash1 = "624e85bd669b97bc55ed5c5ea5f6082a1d4900d235a5d2e2a5683a04e36213e8"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "SOFTWARE\\WOW6432Node\\Microsoft\\config_" ascii
		$ = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\windefenders" ascii

	condition:
		1 of them
}
