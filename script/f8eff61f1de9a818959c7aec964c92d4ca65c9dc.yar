import "pe"

rule case_4485_adf
{
	meta:
		description = "files - file adf.bat"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com"
		date = "2021-07-13"
		hash1 = "f6a377ba145a5503b5eb942d17645502eddf3a619d26a7b60df80a345917aaa2"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "adfind.exe"
		$s2 = "objectcategory=person" fullword ascii
		$s3 = "objectcategory=computer" fullword ascii
		$s4 = "adfind.exe -gcb -sc trustdmp > trustdmp.txt" fullword ascii
		$s5 = "adfind.exe -sc trustdmp > trustdmp.txt" fullword ascii
		$s6 = "adfind.exe -subnets -f (objectCategory=subnet)> subnets.txt" fullword ascii
		$s7 = "(objectcategory=group)" fullword ascii
		$s8 = "(objectcategory=organizationalUnit)" fullword ascii

	condition:
		uint16(0)==0x6463 and filesize <1KB and (1 of ($x*) and 6 of ($s*))
}
