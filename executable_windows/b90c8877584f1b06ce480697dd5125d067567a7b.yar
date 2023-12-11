import "pe"

rule thequickbrow_APT1
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Detects the presence of the APT1 threat group using the string 'thequickbrownfxjmpsvalzydg'"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "thequickbrownfxjmpsvalzydg" wide ascii

	condition:
		all of them
}
