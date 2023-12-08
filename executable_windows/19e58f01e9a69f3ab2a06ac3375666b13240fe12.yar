import "pe"

rule SWORD_APT1
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Detects SWORD APT1 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "@***@*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@>>>" wide ascii
		$s2 = "sleep:" wide ascii
		$s3 = "down:" wide ascii
		$s4 = "*========== Bye Bye ! ==========*" wide ascii

	condition:
		all of them
}
