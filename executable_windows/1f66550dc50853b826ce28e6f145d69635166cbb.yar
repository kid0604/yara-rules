import "pe"

rule APT1_WEBC2_QBP
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Yara rule for detecting APT1 Web C2 activity"
		os = "windows"
		filetype = "executable"

	strings:
		$1 = "2010QBP" wide ascii
		$2 = "adobe_sl.exe" wide ascii
		$3 = "URLDownloadToCacheFile" wide ascii
		$4 = "dnsapi.dll" wide ascii
		$5 = "urlmon.dll" wide ascii

	condition:
		4 of them
}
