import "pe"

rule UniformAlfa
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "a24377681cf56c712e544af01ac8a5dbaa81d16851a17a147bbf5132890d7437"
		description = "Detects UniformAlfa malware attempting to stop or delete a service"
		os = "windows"
		filetype = "executable"

	strings:
		$stopDeleteService = {8D [3] 5? 6A 01 5? FF D?	83 [3] 01 75 ?? 5? FF 15}

	condition:
		$stopDeleteService in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
