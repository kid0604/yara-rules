import "pe"

rule HACKSFASE1_APT1
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Yara rule for detecting APT1 threat known as CommentCrew"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = {cb 39 82 49 42 be 1f 3a}

	condition:
		all of them
}
