import "pe"

rule OPCLEAVER_zhCat
{
	meta:
		description = "Network tool used by Iranian hackers and used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = "70"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Mozilla/4.0 ( compatible; MSIE 7.0; AOL 8.0 )" ascii fullword
		$s2 = "ABC ( A Big Company )" wide fullword

	condition:
		all of them
}
