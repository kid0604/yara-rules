import "pe"

rule pvz_out
{
	meta:
		author = "Cylance"
		date = "2014-12-02"
		description = "http://cylance.com/opcleaver"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Network Connectivity Module" wide
		$s2 = "OSPPSVC" wide

	condition:
		all of them
}
