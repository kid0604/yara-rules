import "pe"

rule ccrewDownloader1
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Detects the presence of CommentCrew threat APT1 downloader"
		os = "windows"
		filetype = "executable"

	strings:
		$a = {DD B5 61 F0 20 47 20 57 D6 65 9C CB 31 1B 65 42}

	condition:
		any of them
}
