rule CVE_2012_0158_KeyBoy
{
	meta:
		author = "Etienne Maynier <etienne@citizenlab.ca>"
		description = "CVE-2012-0158 variant"
		file = "8307e444cad98b1b59568ad2eba5f201"
		os = "windows"
		filetype = "executable"

	strings:
		$a = "d0cf11e0a1b11ae1000000000000000000000000000000003e000300feff09000600000000000000000000000100000001" nocase
		$b = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" nocase
		$c = /5(\{\\b0\}|)[ ]*2006F00(\{\\b0\}|)[ ]*6F007(\{\\b0\}|)[ ]*400200045(\{\\b0\}|)[ ]*006(\{\\b0\}|)[ ]*E007(\{\\b0\}|)[ ]*400720079/ nocase
		$d = "MSComctlLib.ListViewCtrl.2"
		$e = "ac38c874503c307405347aaaebf2ac2c31ebf6e8e3" nocase

	condition:
		all of them
}
