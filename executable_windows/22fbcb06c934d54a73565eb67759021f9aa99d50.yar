import "pe"

rule informational_NtdsAudit_AD_Audit_Tool
{
	meta:
		description = "files - NtdsAudit.exe"
		author = "TheDFIRReport"
		date = "2021-07-25"
		hash1 = "fb49dce92f9a028a1da3045f705a574f3c1997fe947e2c69699b17f07e5a552b"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "WARNING: Use of the --pwdump option will result in decryption of password hashes using the System Key." fullword wide
		$s2 = "costura.nlog.dll.compressed" fullword wide
		$s3 = "costura.microsoft.extensions.commandlineutils.dll.compressed" fullword wide
		$s4 = "Password hashes have only been dumped for the \"{0}\" domain." fullword wide
		$s5 = "The NTDS file contains user accounts with passwords stored using reversible encryption. Use the --dump-reversible option to outp" wide
		$s6 = "costura.system.valuetuple.dll.compressed" fullword wide
		$s7 = "TargetRNtdsAudit.NTCrypto.#DecryptDataUsingAes(System.Byte[],System.Byte[],System.Byte[])T" fullword ascii
		$s8 = "c:\\Code\\NtdsAudit\\src\\NtdsAudit\\obj\\Release\\NtdsAudit.pdb" fullword ascii
		$s9 = "NtdsAudit.exe" fullword wide
		$s10 = "costura.esent.interop.dll.compressed" fullword wide
		$s11 = "costura.costura.dll.compressed" fullword wide
		$s12 = "costura.registry.dll.compressed" fullword wide
		$s13 = "costura.nfluent.dll.compressed" fullword wide
		$s14 = "dumphashes" fullword ascii
		$s15 = "The path to output hashes in pwdump format." fullword wide
		$s16 = "Microsoft.Extensions.CommandLineUtils" fullword ascii
		$s17 = "If you require password hashes for other domains, please obtain the NTDS and SYSTEM files for each domain." fullword wide
		$s18 = "microsoft.extensions.commandlineutils" fullword wide
		$s19 = "-p | --pwdump <file>" fullword wide
		$s20 = "get_ClearTextPassword" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and 1 of ($x*) and 4 of them
}
