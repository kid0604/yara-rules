import "pe"

rule MAL_Winnti_BR_Report_TwinPeaks
{
	meta:
		description = "Detects Winnti samples"
		author = "@br_data repo"
		reference = "https://github.com/br-data/2019-winnti-analyse"
		date = "2019-07-24"
		os = "windows"
		filetype = "executable"

	strings:
		$cooper = "Cooper"
		$pattern = { e9 ea eb ec ed ee ef f0}

	condition:
		uint16(0)==0x5a4d and $cooper and ($pattern in (@cooper[1]..@cooper[1]+100))
}
