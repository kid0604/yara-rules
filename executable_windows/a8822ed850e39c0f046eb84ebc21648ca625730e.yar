rule CrowdStrike_SUNSPOT_02 : artifact stellarparticle sunspot
{
	meta:
		copyright = "(c) 2021 CrowdStrike Inc."
		description = "Detects mutex names in SUNSPOT"
		version = "202101081448"
		date = "2021-01-08"
		actor = "StellarParticle"
		malware_family = "SUNSPOT"
		reference = "https://www.crowdstrike.com/blog/sunspot-malware-technical-analysis/"
		os = "windows"
		filetype = "executable"

	strings:
		$mutex_01 = "{12d61a41-4b74-7610-a4d8-3028d2f56395}" wide ascii
		$mutex_02 = "{56331e4d-76a3-0390-a7ee-567adf5836b7}" wide ascii

	condition:
		any of them and filesize <10MB
}
