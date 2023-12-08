import "pe"

rule CredTheft_MSIL_ADPassHunt_2_alt_1
{
	meta:
		md5 = "6efb58cf54d1bb45c057efcfbbd68a93"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		description = "Detects the presence of the MSIL ADPassHunt credential theft tool"
		os = "windows"
		filetype = "executable"

	strings:
		$pdb1 = "\\ADPassHunt\\"
		$pdb2 = "\\ADPassHunt.pdb"
		$s1 = "Usage: .\\ADPassHunt.exe"
		$s2 = "[ADA] Searching for accounts with msSFU30Password attribute"
		$s3 = "[ADA] Searching for accounts with userpassword attribute"
		$s4 = "[GPP] Searching for passwords now"

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and (@pdb2[1]<@pdb1[1]+50) or 2 of ($s*)
}
