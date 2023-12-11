import "pe"

rule MAL_EXE_LockBit_v2
{
	meta:
		author = "Silas Cutler, modified by Florian Roth"
		description = "Detection for LockBit version 2.x from 2011"
		date = "2023-01-01"
		modified = "2023-01-06"
		version = "1.0"
		score = 80
		hash = "00260c390ffab5734208a7199df0e4229a76261c3f5b7264c4515acb8eb9c2f8"
		DaysofYARA = "1/100"
		os = "windows"
		filetype = "executable"

	strings:
		$s_ransom_note01 = "that is located in every encrypted folder." wide
		$s_ransom_note02 = "Would you like to earn millions of dollars?" wide
		$x_ransom_tox = "3085B89A0C515D2FB124D645906F5D3DA5CB97CEBEA975959AE4F95302A04E1D709C3C4AE9B7" wide
		$x_ransom_url = "http://lockbitapt6vx57t3eeqjofwgcglmutr3a35nygvokja5uuccip4ykyd.onion" wide
		$s_str1 = "Active:[ %d [                  Completed:[ %d" wide
		$x_str2 = "\\LockBit_Ransomware.hta" wide ascii
		$s_str2 = "Ransomware.hta" wide ascii

	condition:
		uint16(0)==0x5A4D and (1 of ($x*) or 2 of them ) or 3 of them
}
