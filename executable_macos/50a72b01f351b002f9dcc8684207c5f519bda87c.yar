import "pe"

rule MALWARE_Osx_MacSearch
{
	meta:
		author = "ditekSHen"
		description = "Detects MacSearch adware"
		os = "macos"
		filetype = "executable"

	strings:
		$s1 = "open -a safari" ascii
		$s2 = "/INDownloader" ascii
		$s3 = "/safefinder" ascii
		$s4 = "/INEncryptor" ascii
		$s5 = "/INInstallerFlow" ascii
		$s6 = "/INConfiguration" ascii
		$s7 = "/INChromeAndFFSetter" ascii
		$s8 = "/INSafariSetter" ascii
		$s9 = "/bin/launchctl" fullword ascii
		$s10 = "/usr/bin/csrutil" fullword ascii
		$s11 = "_Tt%cSs%zu%.*s%s" fullword ascii
		$s12 = "_Tt%c%zu%.*s%zu%.*s%s" fullword ascii
		$s13 = "/macap/safefinder_Obf/safefinder/" ascii
		$s14 = "/safefinder.build/Release/macsearch.build/" ascii

	condition:
		uint16(0)==0xfacf and 10 of them
}
