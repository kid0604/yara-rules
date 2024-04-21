import "pe"

rule informational_AnyDesk_Remote_Software_Utility
{
	meta:
		description = "files - AnyDesk.exe"
		author = "TheDFIRReport"
		date = "2021-07-25"
		hash1 = "9eab01396985ac8f5e09b74b527279a972471f4b97b94e0a76d7563cf27f4d57"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "C:\\Buildbot\\ad-windows-32\\build\\release\\app-32\\win_loader\\AnyDesk.pdb" fullword ascii
		$s2 = "release/win_6.3.x" fullword ascii
		$s3 = "16eb5134181c482824cd5814c0efd636" fullword ascii
		$s4 = "b1bfe2231dfa1fa4a46a50b4a6c67df34019e68a" fullword ascii
		$s5 = "Z72.irZ" fullword ascii
		$s6 = "ysN.JTf" fullword ascii
		$s7 = ",;@O:\"" fullword ascii
		$s8 = "ekX.cFm" fullword ascii
		$s9 = ":keftP" fullword ascii
		$s10 = ">FGirc" fullword ascii
		$s11 = ">-9 -D" fullword ascii
		$s12 = "% /m_v?" fullword ascii
		$s13 = "?\\+ X5" fullword ascii
		$s14 = "Cyurvf7" fullword ascii
		$s15 = "~%f_%Cfcs" fullword ascii
		$s16 = "wV^X(P+ " fullword ascii
		$s17 = "\\Ej0drBTC8E=oF" fullword ascii
		$s18 = "W00O~AK_=" fullword ascii
		$s19 = "D( -m}w" fullword ascii
		$s20 = "avAoInJ1" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <11000KB and 1 of ($x*) and 4 of them
}
