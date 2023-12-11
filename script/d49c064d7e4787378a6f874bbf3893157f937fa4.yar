import "pe"

rule MINIASP_APT1
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Yara rule for detecting MINIASP APT1 threat"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "miniasp" wide ascii
		$s2 = "wakeup=" wide ascii
		$s3 = "download ok!" wide ascii
		$s4 = "command is null!" wide ascii
		$s5 = "device_input.asp?device_t=" wide ascii

	condition:
		all of them
}
