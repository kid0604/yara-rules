rule APT_CobaltStrike_Beacon_Indicator
{
	meta:
		description = "Detects CobaltStrike beacons"
		author = "JPCERT"
		reference = "https://github.com/JPCERTCC/aa-tools/blob/master/cobaltstrikescan.py"
		date = "2018-11-09"
		os = "windows"
		filetype = "executable"

	strings:
		$v1 = { 73 70 72 6E 67 00 }
		$v2 = { 69 69 69 69 69 69 69 69 }

	condition:
		uint16(0)==0x5a4d and filesize <300KB and all of them
}
