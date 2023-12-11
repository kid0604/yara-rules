rule APT_Sandworm_CyclopsBlink_modified_install_upgrade
{
	meta:
		author = "NCSC"
		description = "Detects notable strings identified within the modified install_upgrade executable, embedded within Cyclops Blink"
		hash1 = "3adf9a59743bc5d8399f67cab5eb2daf28b9b863"
		hash2 = "c59bc17659daca1b1ce65b6af077f86a648ad8a8"
		hash3 = "7d61c0dd0cd901221a9dff9df09bb90810754f10"
		hash4 = "438cd40caca70cafe5ca436b36ef7d3a6321e858"
		reference = "https://www.ncsc.gov.uk/news/joint-advisory-shows-new-sandworm-malware-cyclops-blink-replaces-vpnfilter"
		date = "2022-02-23"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "/pending/%010lu_%06d_%03d_p1"
		$ = "/pending/sysa_code_dir/test_%d_%d_%d_%d_%d_%d"
		$ = "etaonrishdlcupfm"
		$ = "/pending/WGUpgrade-dl.new"
		$ = "/pending/bin/install_upgraded"
		$ = {38 80 4C 00}
		$ = {38 80 4C 05}
		$ = {38 80 4C 04}
		$ = {3C 00 48 4D 60 00 41 43 90 09 00 00}

	condition:
		( uint32(0)==0x464c457f) and (6 of them )
}
