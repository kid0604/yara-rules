import "pe"

rule EclipseSunCloudRAT
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Yara rule for detecting EclipseSunCloudRAT malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a = "Eclipse_A" wide ascii
		$b = "\\PJTS\\" wide ascii
		$c = "Eclipse_Client_B.pdb" wide ascii
		$d = "XiaoME" wide ascii
		$e = "SunCloud-Code" wide ascii
		$f = "/uc_server/data/forum.asp" wide ascii

	condition:
		any of them
}
