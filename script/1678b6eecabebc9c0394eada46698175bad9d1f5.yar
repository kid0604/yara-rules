rule APT_UNC4841_ESG_Barracuda_CVE_2023_2868_Forensic_Artifacts_Jun23_1 : SCRIPT
{
	meta:
		description = "Detects forensic artifacts found in the exploitation of CVE-2023-2868 in Barracuda ESG devices by UNC4841"
		author = "Florian Roth"
		reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
		date = "2023-06-15"
		modified = "2023-06-16"
		score = 75
		os = "windows,linux"
		filetype = "script"

	strings:
		$x01 = "=;ee=ba;G=s;_ech_o $abcdefg_${ee}se64" ascii
		$x02 = ";echo $abcdefg | base64 -d | sh" ascii
		$x03 = "setsid sh -c \"mkfifo /tmp/p" ascii
		$x04 = "sh -i </tmp/p 2>&1" ascii
		$x05 = "if string.match(hdr:body(), \"^[%w%+/=" ascii
		$x06 = "setsid sh -c \"/sbin/BarracudaMailService eth0\""
		$x07 = "echo \"set the bvp ok\""
		$x08 = "find ${path} -type f ! -name $excludeFileNameKeyword | while read line ;"
		$x09 = " /mail/mstore | xargs -i cp {} /usr/share/.uc/"
		$x10 = "tar -T /mail/mstore/tmplist -czvf "
		$sa1 = "sh -c wget --no-check-certificate http"
		$sa2 = ".tar;chmod +x "

	condition:
		1 of ($x*) or all of ($sa*)
}
