import "pe"

rule APT1_WEBC2_AUSOV
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Yara rule for detecting APT1 Web C2 Ausov threat"
		os = "windows"
		filetype = "executable"

	strings:
		$1 = "ntshrui.dll" wide ascii
		$2 = "%SystemRoot%\\System32\\" wide ascii
		$3 = "<!--DOCHTML" wide ascii
		$4 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)" wide ascii
		$5 = "Ausov" wide ascii

	condition:
		4 of them
}
