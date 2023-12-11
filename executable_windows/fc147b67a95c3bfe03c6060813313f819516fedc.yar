import "pe"

rule CSIT_14003_03 : installer RAT
{
	meta:
		Author = "CrowdStrike, Inc"
		Date = "2014/05/13"
		Description = "Flying Kitten Installer"
		Reference = "http://blog.crowdstrike.com/cat-scratch-fever-crowdstrike-tracks-newly-reported-iranian-actor-flying-kitten"
		description = "Installer for Flying Kitten RAT"
		os = "windows"
		filetype = "executable"

	strings:
		$exename = "IntelRapidStart.exe"
		$confname = "IntelRapidStart.exe.config"
		$cabhdr = { 4d 53 43 46 00 00 00 00 }

	condition:
		all of them
}
