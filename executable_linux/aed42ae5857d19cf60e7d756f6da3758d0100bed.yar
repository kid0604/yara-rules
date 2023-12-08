import "pe"

rule HKTL_LNX_Pnscan
{
	meta:
		description = "Detects Pnscan port scanner"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/ptrrkssn/pnscan"
		date = "2019-05-27"
		score = 55
		os = "linux"
		filetype = "executable"

	strings:
		$x1 = "-R<hex list>   Hex coded response string to look for." fullword ascii
		$x2 = "This program implements a multithreaded TCP port scanner." ascii wide

	condition:
		filesize <6000KB and 1 of them
}
