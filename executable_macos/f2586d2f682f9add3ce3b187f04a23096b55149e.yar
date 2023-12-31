import "pe"

rule malware_macos_macspy
{
	meta:
		description = "macSpy is a malware-as-a-service (MaaS) product advertised as the most sophisticated Mac spyware ever"
		reference = "https://www.alienvault.com/blogs/labs-research/macspy-os-x-rat-as-a-service"
		author = "AlienVault Labs"
		md5 = "6c03e4a9bcb9afaedb7451a33c214ae4"
		os = "macos"
		filetype = "executable"

	strings:
		$header0 = {cf fa ed fe}
		$header1 = {ce fa ed fe}
		$header2 = {ca fe ba be}
		$c1 = { 76 31 09 00 76 32 09 00 76 33 09 00 69 31 09 00 69 32 09 00 69 33 09 00 69 34 09 00 66 31 09 00 66 32 09 00 66 33 09 00 66 34 09 00 74 63 3A 00 }

	condition:
		($header0 at 0 or $header1 at 0 or $header2 at 0) and $c1
}
