rule searchinject
{
	meta:
		author = "@patrickrolsen"
		reference = "Usage: SearchInject <PID1>[PID2][PID3] - It loads Searcher.dll (appears to be hard coded)"
		description = "Detects the presence of SearchInject malware"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "SearchInject"
		$s2 = "inject base:"
		$s3 = "Searcher.dll" nocase

	condition:
		uint16(0)==0x5A4D and all of ($s*)
}
