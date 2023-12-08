import "pe"

rule WhiskeyBravo
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "74eac0461c40316689ac2d598f606caa3965195b22f23d5acefeedfcdf056c5b"
		Source = "d079a266ed2a852c33cdac3df115d163ebbf2c8dae32d935e895cf8193163b13"
		description = "Detects WhiskeyBravo malware based on specific file extensions and byte patterns"
		os = "windows"
		filetype = "document"

	strings:
		$a = {68 [4] 5? FF D? 83 C4 0C 85 C0 0F 84 [4] [0-2] 68 [4] 5? FF D? 83 C4 0C 85 C0 0F 84 [4] [0-2] 68 [4] 5? FF D? 83 C4 0C 85 C0 0F 84 }
		$ext1 = ".wpd" wide nocase
		$ext2 = ".doc" wide nocase
		$ext3 = ".hwp" wide nocase

	condition:
		2 of ($ext*) and $a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
