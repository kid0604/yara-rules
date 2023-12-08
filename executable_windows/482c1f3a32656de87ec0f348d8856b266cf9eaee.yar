import "pe"

rule FakeTLS_ServerHelloGetSelectedCipher : sharedcode
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "eff542ac8e37db48821cb4e5a7d95c044fff27557763de3a891b40ebeb52cc55.ex_"
		description = "Detects FakeTLS ServerHelloGetSelectedCipher"
		os = "windows"
		filetype = "executable"

	strings:
		$a = {	24 10 	0C 10 	89 ?? 	66 8? [3] 66 3? 00 C0 73 ?? 66 2? 35 00 66 F7 ?? 1B ?? 	2? 80 0? 00 01 00 00 8B ?? 5? }

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
