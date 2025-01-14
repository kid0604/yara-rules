rule MAL_Sophos_XG_Pygmy_Goat_Magic_Strings
{
	meta:
		description = "Detects Pygmy Goat - a native x86-32 ELF shared object that was discovered on Sophos XG firewall devices, providing backdoor access to the device. This detection rule is based on the magic byte sequences used in C2 communications."
		reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/pygmy-goat/ncsc-mar-pygmy-goat.pdf"
		author = "NCSC"
		date = "2024-10-22"
		score = 75
		hash1 = "71f70d61af00542b2e9ad64abd2dda7e437536ff"
		id = "7df6c228-d569-5f1c-8bbb-4194347f99d1"
		os = "linux"
		filetype = "executable"

	strings:
		$c2_magic_handshake = ",bEB3?=o"
		$fake_ssh_banner = "SSH-2.0-D8pjE"
		$fake_ed25519_key = { 29 cc f0 cc 16 c5 46 6e 52 19 82 8e 86
      65 42 8c 1f 1a d4 c3 a5 b1 cb fc c0 26 6c 31 3c 5c 90 3a 24 7d e4 d3 57
      6d da 8e cb f4 66 d1 cb 81 4f 63 fd 4a fa 06 e4 7e 4c a0 95 91 bd cb 97
      a4 b3 0f }

	condition:
		uint32(0)==0x464c457f and any of them
}
