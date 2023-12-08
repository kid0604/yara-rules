import "pe"

rule INDICATOR_RMM_MeshAgent
{
	meta:
		author = "ditekSHen"
		description = "Detects MeshAgent. Review RMM Inventory"
		clamav1 = "INDICATOR.Win.RMM.MeshAgent"
		reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
		reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
		reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
		reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "\\MeshAgent" wide
		$x2 = "Mesh Agent" wide
		$x3 = "MeshDummy" wide
		$x4 = "MeshCentral" wide
		$x5 = "ILibRemoteLogging.c" ascii
		$x6 = "AgentCore/MeshServer_" wide
		$s1 = "var _tmp = 'Detected OS: ' + require('os').Name;" ascii
		$s2 = "console.log(getSHA384FileHash(process.execPath).toString('hex'))" ascii
		$s3 = "ScriptContainer.Create(): Error spawning child process, using [%s]" fullword ascii
		$s4 = "{\"agent\":\"" ascii
		$s6 = "process.versions.commitHash" fullword ascii
		$s7 = "console.log('Error Initializing script from Zip file');process._exit();" fullword ascii

	condition:
		uint16(0)==0x5a4d and (3 of ($x*) or (1 of ($x*) and 3 of ($s*)) or 6 of ($s*))
}
