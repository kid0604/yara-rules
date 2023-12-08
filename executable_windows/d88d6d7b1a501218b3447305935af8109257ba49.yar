import "pe"

rule worm_ms17_010 : worm_ms17_010
{
	meta:
		description = "Detects Worm used during 2017-May-12th WannaCry campaign, which is based on ETERNALBLUE"
		author = "Blueliv"
		reference = "https://blueliv.com/research/wannacrypt-malware-analysis/"
		date = "2017-05-15"
		os = "windows"
		filetype = "executable"

	strings:
		$s01 = "__TREEID__PLACEHOLDER__" ascii
		$s02 = "__USERID__PLACEHOLDER__@" ascii
		$s03 = "SMB3"
		$s05 = "SMBu"
		$s06 = "SMBs"
		$s07 = "SMBr"
		$s08 = "%s -m security" ascii
		$s09 = "%d.%d.%d.%d"
		$payloadwin2000_2195 = "\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x30\x00\x20\x00\x32\x00\x31\x00\x39\x00\x35\x00\x00\x00"
		$payload2000_50 = "\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x30\x00\x20\x00\x35\x00\x2e\x00\x30\x00\x00\x00"

	condition:
		all of them
}
