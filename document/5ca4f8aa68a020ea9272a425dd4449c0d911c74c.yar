rule EXPL_XML_Encoded_CVE_2021_40444
{
	meta:
		author = "James E.C, Proofpoint"
		description = "Detects possible CVE-2021-40444 with no encoding, HTML/XML entity (and hex notation) encoding, or all 3"
		reference = "https://twitter.com/sudosev/status/1439205606129377282"
		date = "2021-09-18"
		modified = "2021-09-19"
		score = 70
		hash = "13DE9F39B1AD232E704B5E0B5051800FCD844E9F661185ACE8287A23E9B3868E"
		hash = "84674ACFFBA5101C8AC518019A9AFE2A78A675EF3525A44DCEDDEED8A0092C69"
		os = "windows,linux,macos"
		filetype = "document"

	strings:
		$h1 = "<?xml " ascii wide
		$t_xml_r = /Target[\s]{0,20}=[\s]{0,20}\["']([Mm]|&#(109|77|x6d|x4d);)([Hh]|&#(104|72|x68|x48);)([Tt]|&#(116|84|x74|x54);)([Mm]|&#(109|77|x6d|x4d);)([Ll]|&#(108|76|x6c|x4c);)(:|&#58;|&#x3a)/
		$t_mode_r = /TargetMode[\s]{0,20}=[\s]{0,20}\["']([Ee]|&#(x45|x65|69|101);)([Xx]|&#(x58|x78|88|120);)([Tt]|&#(x74|x54|84|116);)/

	condition:
		filesize <500KB and $h1 and all of ($t_*)
}
