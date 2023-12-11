import "pe"

rule ShellCreator2
{
	meta:
		author = "Cylance"
		date = "2014-12-02"
		description = "http://cylance.com/opcleaver"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "ShellCreator2.Properties"
		$s2 = "set_IV"

	condition:
		all of them
}
