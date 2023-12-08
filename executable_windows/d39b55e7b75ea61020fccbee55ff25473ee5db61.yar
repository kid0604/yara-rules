rule network_dropper
{
	meta:
		author = "x0r"
		description = "File downloader/dropper"
		version = "0.1"
		os = "windows"
		filetype = "executable"

	strings:
		$f1 = "urlmon.dll" nocase
		$c1 = "URLDownloadToFile"
		$c2 = "URLDownloadToCacheFile"
		$c3 = "URLOpenStream"
		$c4 = "URLOpenPullStream"

	condition:
		$f1 and 1 of ($c*)
}
