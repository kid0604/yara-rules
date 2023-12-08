import "pe"
import "hash"

rule Sodinokibi_032021
{
	meta:
		description = "Detect the risk of Ransomware Sodinokibi Rule 12"
		detail = "Sodinokibi_032021: files - file DomainName.exe"
		hash1 = "2896b38ec3f5f196a9d127dbda3f44c7c29c844f53ae5f209229d56fd6f2a59c"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "vmcompute.exe" fullword wide
		$s2 = "vmwp.exe" fullword wide
		$s3 = "bootcfg /raw /a /safeboot:network /id 1" fullword ascii
		$s4 = "bcdedit /set {current} safeboot network" fullword ascii
		$s5 = "7+a@P>:N:0!F$%I-6MBEFb M" fullword ascii
		$s6 = "jg:\"\\0=Z" fullword ascii
		$s7 = "ERR0R D0UBLE RUN!" fullword wide
		$s8 = "VVVVVPQ" fullword ascii
		$s9 = "VVVVVWQ" fullword ascii
		$s10 = "Running" fullword wide
		$s11 = "expand 32-byte kexpand 16-byte k" fullword ascii
		$s12 = "9RFIT\"&" fullword ascii
		$s13 = "jZXVf9F" fullword ascii
		$s14 = "tCWWWhS=@" fullword ascii
		$s15 = "vmms.exe" fullword wide
		$s16 = "JJwK9Zl" fullword ascii
		$s17 = "KkT37uf4nNh2PqUDwZqxcHUMVV3yBwSHO#K" fullword ascii
		$s18 = "0*090}0" fullword ascii
		$s19 = "5)5I5a5" fullword ascii
		$s20 = "7-7H7c7" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <400KB and (pe.imphash()=="031931d2f2d921a9d906454d42f21be0" or 8 of them )
}
