import "time"
import "pe"

rule INDICATOR_SUSPICOUS_EXE_References_VEEAM
{
	meta:
		author = "ditekSHen"
		description = "Detects executables containing many references to VEEAM. Observed in ransomware"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "VeeamNFSSvc" ascii wide nocase
		$s2 = "VeeamRESTSvc" ascii wide nocase
		$s3 = "VeeamCloudSvc" ascii wide nocase
		$s4 = "VeeamMountSvc" ascii wide nocase
		$s5 = "VeeamBackupSvc" ascii wide nocase
		$s6 = "VeeamBrokerSvc" ascii wide nocase
		$s7 = "VeeamDeploySvc" ascii wide nocase
		$s8 = "VeeamCatalogSvc" ascii wide nocase
		$s9 = "VeeamTransportSvc" ascii wide nocase
		$s10 = "VeeamDeploymentService" ascii wide nocase
		$s11 = "VeeamHvIntegrationSvc" ascii wide nocase
		$s12 = "VeeamEnterpriseManagerSvc" ascii wide nocase
		$s13 = "\"Veeam Backup Catalog Data Service\"" ascii wide nocase
		$e1 = "veeam.backup.agent.configurationservice.exe" ascii wide nocase
		$e2 = "veeam.backup.brokerservice.exe" ascii wide nocase
		$e3 = "veeam.backup.catalogdataservice.exe" ascii wide nocase
		$e4 = "veeam.backup.cloudservice.exe" ascii wide nocase
		$e5 = "veeam.backup.externalinfrastructure.dbprovider.exe" ascii wide nocase
		$e6 = "veeam.backup.manager.exe" ascii wide nocase
		$e7 = "veeam.backup.mountservice.exe" ascii wide nocase
		$e8 = "veeam.backup.service.exe" ascii wide nocase
		$e9 = "veeam.backup.uiserver.exe" ascii wide nocase
		$e10 = "veeam.backup.wmiserver.exe" ascii wide nocase
		$e11 = "veeamdeploymentsvc.exe" ascii wide nocase
		$e12 = "veeamfilesysvsssvc.exe" ascii wide nocase
		$e13 = "veeam.guest.interaction.proxy.exe" ascii wide nocase
		$e14 = "veeamnfssvc.exe" ascii wide nocase
		$e15 = "veeamtransportsvc.exe" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and 3 of them
}
