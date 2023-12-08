import "pe"

rule SynFlooder
{
	meta:
		author = "Cylance"
		date = "2014-12-02"
		description = "http://cylance.com/opcleaver"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Unable to resolve [ %s ]. ErrorCode %d"
		$s2 = "your target's IP is : %s"
		$s3 = "Raw TCP Socket Created successfully."

	condition:
		all of them
}
