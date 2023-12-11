import "pe"

rule ccrewDownloader3
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Detects the presence of the ccrewDownloader3 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a = "ejlcmbv" wide ascii
		$b = "bhxjuisv" wide ascii
		$c = "yqzgrh" wide ascii
		$d = "uqusofrp" wide ascii
		$e = "Ljpltmivvdcbb" wide ascii
		$f = "frfogjviirr" wide ascii
		$g = "ximhttoskop" wide ascii

	condition:
		4 of them
}
