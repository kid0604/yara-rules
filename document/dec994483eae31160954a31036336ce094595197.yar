import "pe"

rule OPCLEAVER_Parviz_Developer
{
	meta:
		description = "Parviz developer known from Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Florian Roth"
		score = "70"
		os = "windows"
		filetype = "document"

	strings:
		$s1 = "Users\\parviz\\documents\\" nocase

	condition:
		$s1
}
