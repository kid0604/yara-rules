import "pe"

rule Zh0uSh311
{
	meta:
		author = "Cylance"
		date = "2014-12-02"
		description = "http://cylance.com/opcleaver"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Zh0uSh311"

	condition:
		all of them
}
