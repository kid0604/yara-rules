import "pe"

rule SEASALT_APT1
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "SEASALT APT1 Yara rule for detecting CommentCrew threat"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 5.00; Windows 98) KSMM" wide ascii
		$s2 = "upfileok" wide ascii
		$s3 = "download ok!" wide ascii
		$s4 = "upfileer" wide ascii
		$s5 = "fxftest" wide ascii

	condition:
		all of them
}
