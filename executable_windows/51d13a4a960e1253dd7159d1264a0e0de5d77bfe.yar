import "pe"

rule MoonProject
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Yara rule for detecting MoonProject threat from APT1 CommentCrew"
		os = "windows"
		filetype = "executable"

	strings:
		$a = "Serverfile is smaller than Clientfile" wide ascii
		$b = "\\M tools\\" wide ascii
		$c = "MoonDLL" wide ascii
		$d = "\\M tools\\" wide ascii

	condition:
		any of them
}
