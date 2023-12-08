import "pe"

rule kagent_alt_1
{
	meta:
		author = "Cylance"
		date = "2014-12-02"
		description = "http://cylance.com/opcleaver"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "kill command is in last machine, going back"
		$s2 = "message data length in B64: %d Bytes"

	condition:
		all of them
}
