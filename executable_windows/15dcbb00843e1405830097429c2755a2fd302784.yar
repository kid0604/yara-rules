import "pe"

rule WhiskeyAlfa
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "1c66e67a8531e3ff1c64ae57e6edfde7bef2352d.ex_"
		description = "Detects WhiskeyAlfa malware based on specific strings and conditions"
		os = "windows"
		filetype = "executable"

	strings:
		$randomBuffer = {E8 [4] B1 ?? F6 E9 88 [3] 4? 81 ?? 00 00 01 00 7C}
		$mbrDiskInfo = {89 ?? 09 C7 ?? 65 00 00 02 00 C7 ?? 15 04 00 00 00 C6 ?? 08 08 C7 ?? 04 00 02 00 00 89 ?? 89 ?? 0D C7 ?? 11 01 00 00 00 89 ?? 69 89 ?? 19 B8 01 00 00 00}
		$mbrReplacement_Decoded = { B4 43 B0 00 CD 13 FE C2 80 FA 84 7C F3 B2 80 BF 65 7C 81 05 00 04 83 55 02 00 83 55 04 00 }
		$mbrReplacement_Encoded = { E7 10 E3 53 9E 40 AD 91 D3 A9 D7 2F A0 E1 D3 EC 36 2F D2 56 53 57 D0 06 51 53 D0 06 57 53 }
		$licKey = "99E2428CCA4309C68AAF8C616EF3306582A64513E55C786A864BC83DAFE0C78585B692047273B0E55275102C664C5217E76B8E67F35FCE385E4328EE1AD139EA6AA26345C4F93000DBBC7EF1579D4F"

	condition:
		$licKey or $mbrReplacement_Decoded or $mbrReplacement_Encoded or $randomBuffer in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size)) or $mbrDiskInfo in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
