rule Base64d_PE
{
	meta:
		description = "Contains a base64-encoded executable"
		author = "Florian Roth"
		date = "2017-04-21"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "TVqQAAIAAAAEAA8A//8AALgAAAA" wide ascii
		$s1 = "TVqQAAMAAAAEAAAA//8AALgAAAA" wide ascii

	condition:
		any of them
}
