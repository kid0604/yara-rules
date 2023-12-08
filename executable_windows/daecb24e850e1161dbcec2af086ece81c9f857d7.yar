import "pe"

rule apt_hellsing_irene
{
	meta:
		Author = "Costin Raiu, Kaspersky Lab"
		Date = "2015-04-07"
		Description = "detection for Hellsing msger irene installer"
		Reference = "http://securelist.com/analysis/publications/69567/the-chronicles-of-the-hellsing-apt-the-empire-strikes-back"
		description = "Detection for Hellsing msger irene installer"
		os = "windows"
		filetype = "executable"

	strings:
		$mz = "MZ"
		$a1 = "\\Drivers\\usbmgr.tmp" wide
		$a2 = "\\Drivers\\usbmgr.sys" wide
		$a3 = "common_loadDriver CreateFile error! "
		$a4 = "common_loadDriver StartService error && GetLastError():%d! "
		$a5 = "irene" wide
		$a6 = "aPLib v0.43 - the smaller the better"

	condition:
		($mz at 0) and (4 of ($a*)) and filesize <500000
}
