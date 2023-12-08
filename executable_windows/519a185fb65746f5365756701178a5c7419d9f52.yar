import "pe"

rule DownloaderPossibleCCrew
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Detects potential Downloader used by CommentCrew threat APT1"
		os = "windows"
		filetype = "executable"

	strings:
		$a = "%s?%.6u" wide ascii
		$b = "szFileUrl=%s" wide ascii
		$c = "status=%u" wide ascii
		$d = "down file success" wide ascii
		$e = "Mozilla/4.0 (compatible; MSIE 6.0; Win32)" wide ascii

	condition:
		all of them
}
