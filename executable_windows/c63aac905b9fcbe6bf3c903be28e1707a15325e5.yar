import "pe"

rule IndiaDelta
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "d7b50b1546653bff68220996190446bdc7fc4e38373715b8848d1fb44fe3f53c"
		description = "Detects the IndiaDelta malware based on specific byte patterns in the .text section"
		os = "windows"
		filetype = "executable"

	strings:
		$a = {FF 15 [4-12] 3? 78 56 34 12 [0-2] 8? ?? 78 56 34 12 [0-10] FF 15}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
