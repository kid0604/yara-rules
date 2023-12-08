import "pe"

rule SUSP_Imphash_Mar23_3
{
	meta:
		description = "Detects imphash often found in malware samples (Maximum 0,25% hits with search for 'imphash:x p:0' on Virustotal) = 99,75% hits"
		license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-23"
		modified = "2023-07-24"
		reference = "Internal Research"
		score = 45
		hash = "b5296cf0eb22fba6e2f68d0c9de9ef7845f330f7c611a0d60007aa87e270c62a"
		hash = "5a5a5f71c2270cea036cd408cde99f4ebf5e04a751c558650f5cb23279babe6d"
		hash = "481b0d9759bfd209251eccb1848048ebbe7bd2c87c5914a894a5bffc0d1d67ff"
		hash = "716ba6ea691d6a391daedf09ae1262f1dc1591df85292bff52ad76611666092d"
		hash = "800d160736335aafab10503f7263f9af37a15db3e88e41082d50f68d0ad2dabd"
		hash = "416155124784b3c374137befec9330cd56908e0e32c70312afa16f8220627a52"
		hash = "21899e226502fe63b066c51d76869c4ec5dbd03570551cea657d1dd5c97e7070"
		hash = "0461830e811d3831818dac5a67d4df736b4dc2e8fb185da439f9338bdb9f69c3"
		hash = "773edc71d52361454156dfd802ebaba2bb97421ce9024a7798dcdee3da747112"
		hash = "fe53b9d820adf3bcddf42976b8af1411e87d9dfd9aa479f12b2db50a5600f348"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5A4D and (pe.imphash()=="afcdf79be1557326c854b6e20cb900a7" or pe.imphash()=="6ed4f5f04d62b18d96b26d6db7c18840" or pe.imphash()=="fc6683d30d9f25244a50fd5357825e79" or pe.imphash()=="2c5f2513605e48f2d8ea5440a870cb9e" or pe.imphash()=="0b5552dccd9d0a834cea55c0c8fc05be") and pe.number_of_signatures==0
}
