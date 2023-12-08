import "pe"

rule RomeoDelta
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "1df2af99fb3b6e31067b06df07b96d0ed0632f85111541a416da9ceda709237c"
		description = "Detects a specific code pattern related to login initialization"
		os = "windows"
		filetype = "executable"

	strings:
		$loginInit = { E8 [4] 33 C0 8A [3] 80 [2] 80 [2] 88 [3] 40 83 F8 10 7C ?? 6A 01 8D [3] 6A 10 5? 8B CB E8	}

	condition:
		$loginInit in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
