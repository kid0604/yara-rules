import "pe"

rule mal_host2_AnyDesk
{
	meta:
		description = "mal - file AnyDesk.exe"
		author = "TheDFIRReport"
		date = "2021-11-29"
		hash1 = "8f09c538fc587b882eecd9cfb869c363581c2c646d8c32a2f7c1ff3763dcb4e7"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x86\" pu" ascii
		$x2 = "C:\\Buildbot\\ad-windows-32\\build\\release\\app-32\\win_loader\\AnyDesk.pdb" fullword ascii
		$s3 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x86\" pu" ascii
		$s4 = "<assemblyIdentity version=\"6.3.2.0\" processorArchitecture=\"x86\" name=\"AnyDesk.AnyDesk.AnyDesk\" type=\"win32\" />" fullword ascii
		$s5 = "4http://crl3.digicert.com/DigiCertAssuredIDRootCA.crl0O" fullword ascii
		$s6 = "(Symantec SHA256 TimeStamping Signer - G3" fullword ascii
		$s7 = "(Symantec SHA256 TimeStamping Signer - G30" fullword ascii
		$s8 = "http://ocsp.digicert.com0N" fullword ascii
		$s9 = "http://www.digicert.com/CPS0" fullword ascii
		$s10 = "Bhttp://cacerts.digicert.com/DigiCertSHA2AssuredIDCodeSigningCA.crt0" fullword ascii
		$s11 = "<description>AnyDesk screen sharing and remote control software.</description>" fullword ascii
		$s12 = "/http://crl3.digicert.com/sha2-assured-cs-g1.crl05" fullword ascii
		$s13 = "/http://crl4.digicert.com/sha2-assured-cs-g1.crl0L" fullword ascii
		$s14 = "%jgmRhZl%" fullword ascii
		$s15 = "5ZW:\"Wfh" fullword ascii
		$s16 = "5HRe:\\" fullword ascii
		$s17 = "ysN.JTf" fullword ascii
		$s18 = "Z72.irZ" fullword ascii
		$s19 = "Ve:\\-Sj7" fullword ascii
		$s20 = "ekX.cFm" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <11000KB and 1 of ($x*) and 4 of them
}
