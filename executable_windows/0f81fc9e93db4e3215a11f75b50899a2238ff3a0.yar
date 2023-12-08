import "pe"

rule MAL_BurningUmbrella_Sample_7
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		hash1 = "a4ce3a356d61fbbb067e1430b8ceedbe8965e0cfedd8fb43f1f719e2925b094a"
		hash2 = "a8bfc1e013f15bc395aa5c047f22ff2344c343c22d420804b6d2f0a67eb6db64"
		hash3 = "959612f2a9a8ce454c144d6aef10dd326b201336a85e69a604e6b3892892d7ed"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and filesize <400KB and pe.imphash()=="f5b113d6708a3927b5cc48f2215fcaff"
}
