import "pe"

rule OPCLEAVER_SynFlooder
{
	meta:
		description = "Malware or hack tool used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = "70"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Unable to resolve [ %s ]. ErrorCode %d"
		$s2 = "your target’s IP is : %s"
		$s3 = "Raw TCP Socket Created successfully."

	condition:
		all of them
}
