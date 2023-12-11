import "pe"

rule MAL_Parite_Malware_May19_2
{
	meta:
		description = "Detects Parite malware based on Imphash"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/"
		date = "2019-05-31"
		hash1 = "c9d8852745e81f3bfc09c0a3570d018ae8298af675e3c6ee81ba5b594ff6abb8"
		hash2 = "8d47b08504dcf694928e12a6aa372e7fa65d0d6744429e808ff8e225aefa5af2"
		hash3 = "285e3f21dd1721af2352196628bada81050e4829fb1bb3f8757a45c221737319"
		hash4 = "b987dcc752d9ceb3b0e6cd4370c28567be44b789e8ed8a90c41aa439437321c5"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and filesize <18000KB and (pe.imphash()=="b132a2719be01a6ef87d9939d785e19e" or pe.imphash()=="78f4f885323ffee9f8fa011455d0523d")
}
