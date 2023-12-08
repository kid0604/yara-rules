import "pe"

rule STARSYPOUND_APT1
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Yara rule for detecting STARSYPOUND APT1 threat"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "*(SY)# cmd" wide ascii
		$s2 = "send = %d" wide ascii
		$s3 = "cmd.exe" wide ascii
		$s4 = "*(SY)#" wide ascii

	condition:
		all of them
}
