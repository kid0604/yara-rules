import "pe"

rule ZhoupinExploitCrew
{
	meta:
		author = "Cylance"
		date = "2014-12-02"
		description = "http://cylance.com/opcleaver"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "zhoupin exploit crew" nocase
		$s2 = "zhopin exploit crew" nocase

	condition:
		1 of them
}
