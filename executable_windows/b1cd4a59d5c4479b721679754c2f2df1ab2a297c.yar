import "pe"

rule INDICATOR_RMM_PDQConnect_Agent
{
	meta:
		author = "ditekSHen"
		description = "Detects PDQ Connect Agent. Review RMM Inventory"
		reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
		reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
		reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
		reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
		os = "windows"
		filetype = "executable"

	strings:
		$api1 = "/devices/register" ascii
		$api2 = "/devices/socket/websocket?device_id=" ascii
		$api3 = "/devices/tasks" ascii
		$api4 = "/devices/auth-challenge" ascii
		$api5 = "/devices/receiver/Url" ascii
		$s1 = "sign_pdq.rs" ascii
		$s2 = "x-pdq-dateCredential=(.+?)/" ascii
		$s3 = "pdq-connect-agent" ascii
		$s4 = "PDQ Connect Agent" ascii
		$s5 = "PDQConnectAgent" ascii
		$s6 = "PDQConnectAgentsrc\\logger.rs" ascii
		$s7 = "-PDQ-Key-IdsUser-Agent" ascii
		$s8 = "\\PDQ\\PDQConnectAgent\\" ascii
		$s9 = "\\pdq_connect_agent.pdb" ascii
		$s10 = "task_ids[]PDQ rover" ascii
		$s11 = "https://app.pdq.com/" ascii

	condition:
		( uint16(0)==0x5a4d or uint16(0)==0xcfd0) and (4 of ($s*) or (3 of ($api*) and 1 of ($s*)))
}
