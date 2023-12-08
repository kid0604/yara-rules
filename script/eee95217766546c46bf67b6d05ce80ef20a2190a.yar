rule LOG_F5_BIGIP_Exploitation_Artefacts_CVE_2021_22986_Mar21_1 : LOG
{
	meta:
		description = "Detects forensic artefacts indicating successful exploitation of F5 BIG IP appliances as reported by NCCGroup"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://research.nccgroup.com/2021/03/18/rift-detection-capabilities-for-recent-f5-big-ip-big-iq-icontrol-rest-api-vulnerabilities-cve-2021-22986/"
		date = "2021-03-20"
		score = 80
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$x1 = "\",\"method\":\"POST\",\"uri\":\"http://localhost:8100/mgmt/tm/util/bash\",\"status\":200," ascii
		$x2 = "[com.f5.rest.app.RestServerServlet] X-F5-Auth-Token doesn't have value, so skipping" ascii

	condition:
		1 of them
}
