rule iKAT_startbar
{
	meta:
		description = "Tool to hide unhide the windows startbar from command line - iKAT hack tools - file startbar.exe"
		author = "Florian Roth"
		date = "05.11.14"
		score = 50
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "0cac59b80b5427a8780168e1b85c540efffaf74f"
		os = "windows"
		filetype = "executable"

	strings:
		$s2 = "Shinysoft Limited1" fullword ascii
		$s3 = "Shinysoft Limited0" fullword ascii
		$s4 = "Wellington1" fullword ascii
		$s6 = "Wainuiomata1" fullword ascii
		$s8 = "56 Wright St1" fullword ascii
		$s9 = "UTN-USERFirst-Object" fullword ascii
		$s10 = "New Zealand1" fullword ascii

	condition:
		all of them
}
