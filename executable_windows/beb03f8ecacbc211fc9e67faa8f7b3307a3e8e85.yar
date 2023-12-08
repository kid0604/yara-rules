import "pe"

rule MALWARE_Win_InvalidPrinter
{
	meta:
		author = "ditekSHen"
		description = "Invalid Printer (in2al5d p3in4er) Loader"
		clamav_sig = "MALWARE.Win.InvalidPrinter"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "in2al5d p3in4er" fullword ascii
		$s2 = "CreateDXGIFactory" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <15000KB and all of them
}
