import "pe"

rule MAL_BurningUmbrella_Sample_6
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		hash1 = "49ef2b98b414c321bcdbab107b8fa71a537958fe1e05ae62aaa01fe7773c3b4b"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "ExecuteFile=\"hidcon:nowait:\\\"Word\\\\r.bat\\\"\"" fullword ascii
		$s2 = "InstallPath=\"%Appdata%\\\\Microsoft\"" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and 1 of them
}
