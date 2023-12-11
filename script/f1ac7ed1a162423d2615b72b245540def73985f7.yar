rule EquationGroup_jscan
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file jscan"
		author = "Florian Roth"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		date = "2017-04-08"
		hash1 = "8075f56e44185e1be26b631a2bad89c5e4190c2bfc9fa56921ea3bbc51695dbe"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s1 = "$scanth = $scanth . \" -s \" . $scanthreads;" fullword ascii
		$s2 = "print \"java -jar jscanner.jar$scanth$list\\n\";" fullword ascii

	condition:
		filesize <250KB and 1 of them
}
