rule NoEscape_Ransomware
{
	meta:
		author = "Aziz Farghly @farghlymal"
		description = "Detects NoEscape Ransomware"
		sharing = "TLP:WHITE"
		hash = "68ff9855262b7a9c27e349c5e3bf68b2fc9f9ca32a9d2b844f2265dccd2bc0d8"
		hash2 = "68e5caa3f0fd4adc595b1163bf0dd30ca621c5d7a6ad0a20dfa1968346daa3c8"
		hash3 = "68e5caa3f0fd4adc595b1163bf0dd30ca621c5d7a6ad0a20dfa1968346daa3c8"
		hash4 = "8FAF3B4047CD810CA30A6D7174542DC1E1270AD63662AE2F53D222A8A9113AF8"
		date = "04/05/2024"
		os = "windows"
		filetype = "executable"

	strings:
		$op1 = {83 F8 01 75 0A E8 [4] 5? 8B E5 5D C3 83 F8 02 75 0A E8 [4] 5? 8B E5 5D C3 83 F8 03 75 0A E8 [4] 5? 8B E5 5D C3
        83 F8 04 74 ?? 83 F8 05 75 0A E8 [4] 5? 8B E5 5D C3 83 F8 06 75 ?? E8 [4] 8B ?? E8 [4] 8B ?? E8 [4] 8B ??
        E8 [4] 8B ?? E8 [4] 5? 8B E5 5D C3
        }
		$s1 = "Trigger1" wide ascii
		$s2 = "Trigger2" wide ascii

	condition:
		uint16(0)==0x5A4D and all of them
}
