rule case_5087_3
{
	meta:
		description = "Files - file 3.exe"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com"
		date = "2021-08-30"
		hash1 = "37b264e165e139c3071eb1d4f9594811f6b983d8f4b7ef1fe56ebf3d1f35ac89"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "https://sectigo.com/CPS0" fullword ascii
		$s2 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl0v" fullword ascii
		$s3 = "2http://crl.comodoca.com/AAACertificateServices.crl04" fullword ascii
		$s4 = "3http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt0%" fullword ascii
		$s5 = "        <requestedExecutionLevel level=\"asInvoker\"/>" fullword ascii
		$s6 = "http://ocsp.sectigo.com0" fullword ascii
		$s7 = "2http://crt.sectigo.com/SectigoRSACodeSigningCA.crt0#" fullword ascii
		$s8 = "2http://crl.sectigo.com/SectigoRSACodeSigningCA.crl0s" fullword ascii
		$s9 = "ealagi@aol.com0" fullword ascii
		$s10 = "bhfatmxx" fullword ascii
		$s11 = "orzynoxl" fullword ascii
		$s12 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
		$s13 = "      <!--The ID below indicates application support for Windows 8.1 -->" fullword ascii
		$s14 = "      <!--The ID below indicates application support for Windows 8 -->" fullword ascii
		$s15 = "O:\\-e%" fullword ascii
		$s16 = "      <!--The ID below indicates application support for Windows 10 -->" fullword ascii
		$s17 = "      <!--The ID below indicates application support for Windows 7 -->" fullword ascii
		$s18 = "      <!--The ID below indicates application support for Windows Vista -->" fullword ascii
		$s19 = "  <compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">" fullword ascii
		$s20 = "  </compatibility>" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and 8 of them
}
