import "pe"

rule EXPL_Strings_CVE_POC_May19_1
{
	meta:
		description = "Detects strings used in CVE POC noticed in May 2019"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/"
		date = "2019-05-31"
		score = 80
		hash1 = "01c3882e8141a25abe37bb826ab115c52fd3d109c4a1b898c0c78cee8dac94b4"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "\\Debug\\poc_cve_20" ascii
		$x2 = "\\Release\\poc_cve_20" ascii
		$x3 = "alloc fake fail: %x!" fullword ascii
		$x4 = "Allocate fake tagWnd fail!" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <400KB and 1 of them
}
