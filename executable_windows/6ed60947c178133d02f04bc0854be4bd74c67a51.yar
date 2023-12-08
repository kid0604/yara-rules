import "pe"

rule RegSubDatStrings : RegSubDat Family
{
	meta:
		description = "RegSubDat Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-07-14"
		os = "windows"
		filetype = "executable"

	strings:
		$avg1 = "Button"
		$avg2 = "Allow"
		$avg3 = "Identity Protection"
		$avg4 = "Allow for all"
		$avg5 = "AVG Firewall Asks For Confirmation"
		$mutex = "0x1A7B4C9F"

	condition:
		all of ($avg*) or $mutex
}
