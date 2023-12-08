import "pe"

rule Rehashed_RAT_3
{
	meta:
		description = "Detects malware from Rehashed RAT incident"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blog.fortinet.com/2017/09/05/rehashed-rat-used-in-apt-campaign-against-vietnamese-organizations"
		date = "2017-09-08"
		modified = "2022-12-21"
		hash1 = "9cebae97a067cd7c2be50d7fd8afe5e9cf935c11914a1ab5ff59e91c1e7e5fc4"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "\\BisonNewHNStubDll\\Release\\Goopdate.pdb" ascii
		$s2 = "psisrndrx.ebd" fullword wide
		$s3 = "pbad exception" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and (1 of ($x*) or 2 of them )
}
