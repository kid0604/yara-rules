import "pe"

rule RomeoHotel
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source_64 = "440cb3f6dd07e2f9e3d3614fd23d3863ecfc08b463b0b327eedf08504f838c90"
		Source_diskSpace = "1b1496f8f35d32a93c7f16ebff6e9b560a158cc6fce061491f91bc9f43ef5be4"
		description = "Detects suspicious activity related to disk space and window station manipulation"
		os = "windows"
		filetype = "executable"

	strings:
		$randBuff64 = {E8 [4] 44 [2] 44 [2] B? 1F 85 EB 51 48 [2] 41 [2] C1 ?? 05 8B ?? C1 ?? 1F 03 ??	6B ?? 64 44 [2]	41 [2] 3C}
		$diskSpace = {FF 15 [4] 85 C0 74 ?? 8B [6] 6A 00 99 68 00 00 10 00 5? 5? E8}
		$winst = "winsta0\\default" wide

	condition:
		$randBuff64 in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size)) or ($diskSpace in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size)) and $winst)
}
