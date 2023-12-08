import "pe"

rule BISCUIT_GREENCAT_APT1
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "BISCUIT_GREENCAT_APT1 rule for detecting CommentCrew-threat-apt1"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "zxdosml" wide ascii
		$s2 = "get user name error!" wide ascii
		$s3 = "get computer name error!" wide ascii
		$s4 = "----client system info----" wide ascii
		$s5 = "stfile" wide ascii
		$s6 = "cmd success!" wide ascii

	condition:
		all of them
}
