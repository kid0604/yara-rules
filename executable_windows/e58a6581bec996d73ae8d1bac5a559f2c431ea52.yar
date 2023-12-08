import "hash"

rule RansomHouseRule4
{
	meta:
		description = "Detect the Malware of RansomHouse Rule 4, if you need help, call NSFOCUS's support team 400-8186868, please."
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "OxyKeyScout.exe" fullword wide
		$s2 = "https://sectigo.com/CPS0" fullword ascii
		$s3 = "https://sectigo.com/CPS0C" fullword ascii
		$s4 = "N$.DlL" fullword ascii
		$s5 = "3http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt0%" fullword ascii
		$s6 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl0v" fullword ascii
		$s7 = ",https://enigmaprotector.com/taggant/user.crl0" fullword ascii
		$s8 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
		$s9 = "(Symantec SHA256 TimeStamping Signer - G3" fullword ascii
		$s10 = "(Symantec SHA256 TimeStamping Signer - G30" fullword ascii
		$s11 = "http://ocsp.sectigo.com0&" fullword ascii
		$s12 = "http://ocsp.sectigo.com0" fullword ascii
		$s13 = "support@oxygen-forensic.com0" fullword ascii
		$s14 = "2http://crt.sectigo.com/SectigoRSACodeSigningCA.crt0#" fullword ascii
		$s15 = "2http://crl.sectigo.com/SectigoRSACodeSigningCA.crl0s" fullword ascii
		$s16 = "3http://crl.sectigo.com/SectigoRSATimeStampingCA.crl0t" fullword ascii
		$s17 = "+https://enigmaprotector.com/taggant/spv.crl0" fullword ascii
		$s18 = "3http://crt.sectigo.com/SectigoRSATimeStampingCA.crt0#" fullword ascii
		$s19 = "NNkz:\"J" fullword ascii
		$s20 = "ETCkW:\\" fullword ascii
		$op0 = { a4 00 0c 01 c8 d4 f2 af 34 50 c5 1b 1b 55 03 fc }
		$op1 = { d3 0f 0c 01 34 0f 0c 01 }
		$op2 = { 54 41 47 47 00 30 00 00 b6 1a 00 00 01 00 30 82 }

	condition:
		uint16(0)==0x5a4d and filesize <244000KB and (8 of them and all of ($op*))
}
