import "pe"

rule DAIRY_APT1
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Yara rule for detecting CommentCrew-threat-apt1"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Mozilla/4.0 (compatible; MSIE 7.0;)" wide ascii
		$s2 = "KilFail" wide ascii
		$s3 = "KilSucc" wide ascii
		$s4 = "pkkill" wide ascii
		$s5 = "pklist" wide ascii

	condition:
		all of them
}
