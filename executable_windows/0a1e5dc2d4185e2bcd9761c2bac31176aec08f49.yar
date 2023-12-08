import "pe"

rule SUSP_PDB_CN_Threat_Actor_May19_1
{
	meta:
		description = "Detects PDB path user name used by Chinese threat actors"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/"
		date = "2019-05-31"
		score = 65
		hash1 = "01c3882e8141a25abe37bb826ab115c52fd3d109c4a1b898c0c78cee8dac94b4"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "C:\\Users\\zcg\\Desktop\\" ascii

	condition:
		uint16(0)==0x5a4d and filesize <400KB and 1 of them
}
