rule INDICATOR_KB_GoBuildID_BioPassDropper
{
	meta:
		author = "ditekSHen"
		description = "Detects Golang Build IDs in BioPass dropper"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Go build ID: \"OS0VlkdEIlcl3WDDr9Za/_oVwEipaaX6V4mEEYg2V/PytlyeIYgV65maz4wT2Y/IQvgbHv3bbLV42i10qq2\"" ascii

	condition:
		uint16(0)==0x5a4d and 1 of them
}
