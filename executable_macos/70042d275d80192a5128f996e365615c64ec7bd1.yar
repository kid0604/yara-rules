import "pe"

rule MALWARE_Osx_MaxOfferDeal
{
	meta:
		author = "ditekSHen"
		description = "Detects macOS MaxOfferDeal adware"
		clamav_sig = "MALWARE.Osx.Adware.MaxOfferDeal"
		os = "macos"
		filetype = "executable"

	strings:
		$s1 = "clEvE15obfuscated_data" ascii
		$s2 = "%.*s.%.*s" fullword ascii
		$s3 = "_Tt%cSs%zu%.*s%s" fullword ascii
		$s4 = "_Tt%c%zu%.*s%zu%.*s%s" fullword ascii
		$s5 = "__ZL20tFirefoxProfilesPath" ascii
		$s6 = "__ZL22tFirefoxSearchFileName" ascii
		$s7 = "__ZL37tFirefoxDefaultProfileFolderExtension" ascii
		$s8 = "__ZL21tFirefoxPrefsFileName" ascii
		$s9 = "__GLOBAL__sub_I_Firefox.mm" ascii
		$s10 = "add_image_hook_" ascii
		$s11 = "/Library/Caches/com.apple.xbs/Sources/arclite/arclite-66/source/" fullword ascii

	condition:
		uint16(0)==0xfacf and all of them
}
