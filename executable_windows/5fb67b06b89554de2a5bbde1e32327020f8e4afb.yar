import "pe"

rule gholeeV1
{
	meta:
		Author = "@GelosSnake"
		Date = "2014/08"
		Description = "Gholee first discovered variant "
		Reference = "http://securityaffairs.co/wordpress/28170/cyber-crime/gholee-malware.html"
		description = "Gholee first discovered variant"
		os = "windows"
		filetype = "executable"

	strings:
		$a = "sandbox_avg10_vc9_SP1_2011"
		$b = "gholee"

	condition:
		all of them
}
