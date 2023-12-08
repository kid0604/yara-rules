import "pe"

rule memory_shylock
{
	meta:
		author = "https://github.com/jackcr/"
		description = "Detects memory strings related to Shylock malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a = /pipe\\[A-F0-9]{32}/
		$b = /id=[A-F0-9]{32}/
		$c = /MASTER_[A-F0-9]{32}/
		$d = "***Load injects by PIPE (%s)"
		$e = "***Load injects url=%s (%s)"
		$f = "*********************** Ping Ok ************************"
		$g = "*** LOG INJECTS *** %s"

	condition:
		any of them
}
