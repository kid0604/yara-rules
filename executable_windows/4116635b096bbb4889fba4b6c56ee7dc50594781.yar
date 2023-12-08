rule iKAT_command_lines_agent
{
	meta:
		description = "iKAT hack tools set agent - file ikat.exe"
		author = "Florian Roth"
		date = "05.11.14"
		score = 75
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "c802ee1e49c0eae2a3fc22d2e82589d857f96d94"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Extended Module: super mario brothers" fullword ascii
		$s1 = "Extended Module: " fullword ascii
		$s3 = "ofpurenostalgicfeeling" fullword ascii
		$s8 = "-supermariobrotheretic" fullword ascii
		$s9 = "!http://132.147.96.202:80" fullword ascii
		$s12 = "iKAT Exe Template" fullword ascii
		$s15 = "withadancyflavour.." fullword ascii
		$s16 = "FastTracker v2.00   " fullword ascii

	condition:
		4 of them
}
