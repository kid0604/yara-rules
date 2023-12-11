rule Windows_Ransomware_Bitpaymer_bca25ac6 : beta
{
	meta:
		author = "Elastic Security"
		id = "bca25ac6-e351-4823-be75-b0661c89588a"
		fingerprint = "2ecc7884d47ca7dbba30ba171b632859914d6152601ea7b463c0f52be79ebb8c"
		creation_date = "2020-06-25"
		last_modified = "2021-08-23"
		description = "Identifies BITPAYMER ransomware"
		threat_name = "Windows.Ransomware.Bitpaymer"
		reference = "https://www.welivesecurity.com/2018/01/26/friedex-bitpaymer-ransomware-work-dridex-authors/"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "RWKGGE.PDB" fullword
		$a2 = "*Qf69@+mESRA.RY7*+6XEF#NH.pdb" fullword
		$a3 = "04QuURX.pdb" fullword
		$a4 = "9nuhuNN.PDB" fullword
		$a5 = "mHtXGC.PDB" fullword
		$a6 = "S:\\Work\\_bin\\Release-Win32\\wp_encrypt_new.pdb" fullword
		$a7 = "C:\\Work\\_bin\\Release-Win32\\wp_encrypt.pdb" fullword
		$a8 = "k:\\softcare\\release\\h2O.pdb" fullword

	condition:
		1 of ($a*)
}
