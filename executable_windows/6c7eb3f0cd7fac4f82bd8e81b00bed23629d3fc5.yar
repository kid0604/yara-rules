import "pe"

rule ccrewSSLBack1
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Yara rule for detecting CommentCrew threat APT1"
		os = "windows"
		filetype = "executable"

	strings:
		$a = "!@#%$^#@!" wide ascii
		$b = "64.91.80.6" wide ascii

	condition:
		any of them
}
