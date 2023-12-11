import "pe"

rule apt_hellsing_proxytool
{
	meta:
		Author = "Costin Raiu, Kaspersky Lab"
		Date = "2015-04-07"
		Description = "detection for Hellsing proxy testing tool"
		Reference = "http://securelist.com/analysis/publications/69567/the-chronicles-of-the-hellsing-apt-the-empire-strikes-back"
		description = "Detection for Hellsing proxy testing tool"
		os = "windows"
		filetype = "executable"

	strings:
		$mz = "MZ"
		$a1 = "PROXY_INFO: automatic proxy url => %s "
		$a2 = "PROXY_INFO: connection type => %d "
		$a3 = "PROXY_INFO: proxy server => %s "
		$a4 = "PROXY_INFO: bypass list => %s "
		$a5 = "InternetQueryOption failed with GetLastError() %d"
		$a6 = "D:\\Hellsing\\release\\exe\\exe\\" nocase

	condition:
		($mz at 0) and (2 of ($a*)) and filesize <300000
}
