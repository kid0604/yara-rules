rule case_23869_document_468
{
	meta:
		creation_date = "2024-03-30"
		status = "TESTING"
		sharing = "TLP:WHITE"
		source = "THEDFIRREPORT.COM"
		author = "TDR"
		description = "iceid loader"
		category = "MALWARE"
		malware = "iceid_loader"
		reference = "https://thedfirreport.com/2024/04/29/from-icedid-to-dagon-locker-ransomware-in-29-days/"
		hash = "f6e5dbff14ef272ce07743887a16decbee2607f512ff2a9045415c8e0c05dbb4"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "quisquamEtVeniamOccaecati" fullword
		$s2 = "temporaImpeditQuiPraesentiumEligendiOptio" fullword
		$s3 = "fugiatSaepeQuiaPorroExplicaboExercitationemMaiores" fullword

	condition:
		all of them
}
